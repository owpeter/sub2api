package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type claudePrivacyContextKey int

const (
	claudePrivacyEnabledKey claudePrivacyContextKey = iota
	claudePrivacyPreparedKey
)

// ClaudePrivacyError contains only fixed diagnostics, never client input.
type ClaudePrivacyError struct {
	Status int
	Code   string
}

func (e *ClaudePrivacyError) Error() string { return e.Code }

// Preserve typed control flow for failover while preventing callers from
// logging an arbitrary upstream response through err.Error().
type claudePrivacyForwardError struct{ cause error }

func (e *claudePrivacyForwardError) Error() string { return "privacy_forward_error" }
func (e *claudePrivacyForwardError) Unwrap() error { return e.cause }

func claudePrivacySafeError(ctx context.Context, err error) error {
	if err == nil || !ClaudeIdentityPrivacyEnabled(ctx) {
		return err
	}
	var privacyErr *ClaudePrivacyError
	if errors.As(err, &privacyErr) {
		return privacyErr
	}
	return &claudePrivacyForwardError{cause: err}
}

func privacyInputError(code string) error {
	return &ClaudePrivacyError{Status: http.StatusBadRequest, Code: "privacy_" + code}
}

func privacyConfigError(code string) error {
	return &ClaudePrivacyError{Status: http.StatusServiceUnavailable, Code: "privacy_" + code}
}

// MarkClaudeIdentityPrivacy protects diagnostics even when parsing fails.
func MarkClaudeIdentityPrivacy(ctx context.Context) context.Context {
	return context.WithValue(ctx, claudePrivacyEnabledKey, true)
}

func ClaudeIdentityPrivacyEnabled(ctx context.Context) bool {
	return ctx != nil && ctx.Value(claudePrivacyEnabledKey) == true
}

func WithPreparedClaudePrivacy(ctx context.Context, prepared *PreparedClaudePrivacy) context.Context {
	return context.WithValue(MarkClaudeIdentityPrivacy(ctx), claudePrivacyPreparedKey, prepared)
}

func preparedClaudePrivacy(ctx context.Context) *PreparedClaudePrivacy {
	if ctx == nil {
		return nil
	}
	p, _ := ctx.Value(claudePrivacyPreparedKey).(*PreparedClaudePrivacy)
	return p
}

func ClaudePrivacyRoutingKey(ctx context.Context) (string, bool) {
	if p := preparedClaudePrivacy(ctx); p != nil {
		return p.routingKey, true
	}
	return "", false
}

// ValidateClaudePrivacyTarget is also called before dispatch to other adapters.
func ValidateClaudePrivacyTarget(ctx context.Context, account *Account) error {
	if !ClaudeIdentityPrivacyEnabled(ctx) {
		return nil
	}
	if preparedClaudePrivacy(ctx) == nil {
		return privacyConfigError("not_prepared")
	}
	if account == nil || account.ID <= 0 || account.Platform != PlatformAnthropic || !account.IsOAuth() {
		return privacyConfigError("unsupported_upstream")
	}
	return nil
}

// ClaudeIdentityPrivacy owns the key; prepared state keeps seeds, never raw IDs.
type ClaudeIdentityPrivacy struct {
	key       []byte
	namespace string
}

func NewClaudeIdentityPrivacy(cfg config.ClaudeIdentityPrivacyConfig) (*ClaudeIdentityPrivacy, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(cfg.Key))
	if err != nil || len(key) != 32 || strings.TrimSpace(cfg.Namespace) == "" || len(cfg.Namespace) > 128 {
		return nil, privacyConfigError("key_not_configured")
	}
	return &ClaudeIdentityPrivacy{key: key, namespace: strings.TrimSpace(cfg.Namespace)}, nil
}

type ClaudePrivacyInput struct {
	GroupID     int64
	APIKeyID    int64
	CountTokens bool
	Body        []byte
	Headers     http.Header
}

// PreparedClaudePrivacy is immutable after Prepare. Each Apply starts from
// its ingress aliases, so retry/failover never hashes a previous wire identity.
type PreparedClaudePrivacy struct {
	owner         *ClaudeIdentityPrivacy
	body          []byte
	headers       http.Header
	deviceSeed    string
	sessionSeed   string
	agentSeed     string
	parentSeed    string
	promptSeed    string
	routingKey    string
	ingressUserID string
	hasMetadata   bool
	jsonMetadata  bool
	countTokens   bool
}

func (p *PreparedClaudePrivacy) IngressBody() []byte         { return bytes.Clone(p.body) }
func (p *PreparedClaudePrivacy) IngressHeaders() http.Header { return p.headers.Clone() }

func (s *ClaudeIdentityPrivacy) digest(parts ...string) string {
	m := hmac.New(sha256.New, s.key)
	for _, part := range append([]string{"claude-identity-privacy/v1", s.namespace}, parts...) {
		_ = binary.Write(m, binary.BigEndian, uint32(len(part)))
		_, _ = io.WriteString(m, part)
	}
	return hex.EncodeToString(m.Sum(nil))
}

// RFC 4122 UUIDv5 encoding of an already secret-key-derived value. This is a
// gateway pseudonym, not a claim to reproduce the CLI's random UUID algorithm.
func privacyUUID(seed string) string { return uuid.NewSHA1(uuid.NameSpaceOID, []byte(seed)).String() }

var privacyUserAgent = regexp.MustCompile(`^claude-cli/([0-9]+\.[0-9]+\.[0-9]+) \(external, (cli|sdk-cli)\)(?:[ \t].*)?$`)

func canonicalPrivacyUserAgent(value string) (string, error) {
	if len(value) > 1024 || strings.ContainsAny(value, "\r\n\x00") {
		return "", privacyInputError("unsupported_client")
	}
	m := privacyUserAgent.FindStringSubmatch(value)
	if m == nil {
		return "", privacyInputError("unsupported_client")
	}
	return "claude-cli/" + m[1] + " (external, " + m[2] + ")", nil
}

// Reject ambiguous JSON before gjson/sjson or encoding/json can choose
// different occurrences. Strings containing JSON are validated separately.
func validatePrivacyJSON(data []byte) error {
	if !utf8.Valid(data) {
		return privacyInputError("invalid_json")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 128 {
			return privacyInputError("invalid_json")
		}
		token, err := decoder.Token()
		if err != nil {
			return privacyInputError("invalid_json")
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				t, err := decoder.Token()
				key, ok := t.(string)
				if err != nil || !ok || seen[key] {
					return privacyInputError("ambiguous_json")
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return privacyInputError("invalid_json")
		}
		_, err = decoder.Token()
		if err != nil {
			return privacyInputError("invalid_json")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return privacyInputError("invalid_json")
	}
	return nil
}

func privacyHeaders(headers http.Header) (http.Header, error) {
	out := make(http.Header)
	seen := make(map[string]bool)
	for key, values := range headers {
		key = strings.ToLower(key)
		// Identity/protocol fields must have exactly one unambiguous value,
		// including non-canonical duplicate map keys in internal callers.
		if strings.HasPrefix(key, "x-claude-code-") || strings.HasPrefix(key, "anthropic-") ||
			strings.HasPrefix(key, "x-stainless-") || key == "user-agent" || key == "x-client-request-id" {
			if len(values) != 1 || seen[key] || len(values[0]) > 8192 || strings.ContainsAny(values[0], "\r\n\x00") {
				return nil, privacyInputError("ambiguous_headers")
			}
			out.Set(key, values[0])
			seen[key] = true
		}
	}
	return out, nil
}

func parsePrivacyUserID(raw string) (*ParsedUserID, error) {
	if len(raw) == 0 || len(raw) > 2048 {
		return nil, privacyInputError("invalid_metadata")
	}
	if strings.HasPrefix(strings.TrimSpace(raw), "{") {
		if err := validatePrivacyJSON([]byte(raw)); err != nil {
			return nil, err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &fields); err != nil {
			return nil, privacyInputError("invalid_metadata")
		}
		for key := range fields {
			if key != "device_id" && key != "account_uuid" && key != "session_id" {
				return nil, privacyInputError("unsupported_metadata")
			}
		}
	}
	parsed := ParseMetadataUserID(raw)
	if parsed == nil || len(parsed.DeviceID) > 256 || len(parsed.AccountUUID) > 128 {
		return nil, privacyInputError("invalid_metadata")
	}
	session, err := uuid.Parse(parsed.SessionID)
	if err != nil || len(parsed.SessionID) != 36 {
		return nil, privacyInputError("invalid_session")
	}
	parsed.SessionID = session.String()
	return parsed, nil
}

func formatPrivacyUserID(device, account, session string, asJSON bool) string {
	if asJSON {
		b, _ := json.Marshal(jsonUserID{DeviceID: device, AccountUUID: account, SessionID: session})
		return string(b)
	}
	return "user_" + device + "_account_" + account + "_session_" + session
}

func (s *ClaudeIdentityPrivacy) Prepare(input ClaudePrivacyInput) (*PreparedClaudePrivacy, error) {
	if input.GroupID <= 0 || input.APIKeyID <= 0 {
		return nil, privacyConfigError("invalid_scope")
	}
	if err := validatePrivacyJSON(input.Body); err != nil {
		return nil, err
	}
	root := gjson.ParseBytes(input.Body)
	if !root.IsObject() {
		return nil, privacyInputError("invalid_json")
	}
	if guards := root.Get("safeguards"); guards.Exists() && guards.Raw != "null" {
		// The v1 implementation cannot safely redact classifier inputs.
		if !guards.IsArray() || len(guards.Array()) != 0 {
			return nil, privacyInputError("incompatible_classifier_context")
		}
	}
	headers, err := privacyHeaders(input.Headers)
	if err != nil {
		return nil, err
	}
	ua, err := canonicalPrivacyUserAgent(headers.Get("User-Agent"))
	if err != nil {
		return nil, err
	}
	p := &PreparedClaudePrivacy{owner: s, countTokens: input.CountTokens, headers: make(http.Header), body: bytes.Clone(input.Body)}
	p.headers.Set("User-Agent", ua)
	group, key := strconv.FormatInt(input.GroupID, 10), strconv.FormatInt(input.APIKeyID, 10)
	seed := func(domain, value string) string { return s.digest(domain, group, key, value) }
	metadata := root.Get("metadata")
	var session string
	if metadata.Exists() && metadata.Raw != "null" {
		if !metadata.IsObject() {
			return nil, privacyInputError("invalid_metadata")
		}
		for name := range metadata.Map() {
			if name != "user_id" {
				return nil, privacyInputError("unsupported_metadata")
			}
		}
		if uid := metadata.Get("user_id"); uid.Exists() {
			if uid.Type != gjson.String {
				return nil, privacyInputError("invalid_metadata")
			}
			identity, err := parsePrivacyUserID(uid.String())
			if err != nil {
				return nil, err
			}
			p.hasMetadata, p.jsonMetadata = true, identity.IsNewFormat
			p.deviceSeed = seed("device-seed", identity.DeviceID)
			session = identity.SessionID
		}
	}
	if value := headers.Get("X-Claude-Code-Session-Id"); value != "" {
		id, err := uuid.Parse(value)
		if err != nil || len(value) != 36 {
			return nil, privacyInputError("invalid_session")
		}
		if session != "" && session != id.String() {
			return nil, privacyInputError("session_mismatch")
		}
		session = id.String()
	}
	// The CLI's one-token Haiku authentication probe can omit identity,
	// like count_tokens. Never invent a device/session for these helpers.
	probe := root.Get("max_tokens").Int() == 1 && strings.Contains(strings.ToLower(root.Get("model").String()), "haiku")
	if session == "" && !input.CountTokens && !probe {
		return nil, privacyInputError("missing_session")
	}
	if session != "" {
		p.sessionSeed = seed("session-seed", session)
		p.routingKey = s.digest("routing", p.sessionSeed)
		if headers.Get("X-Claude-Code-Session-Id") != "" {
			p.headers.Set("X-Claude-Code-Session-Id", privacyUUID(p.sessionSeed))
		}
	}
	if p.hasMetadata {
		p.ingressUserID = formatPrivacyUserID(p.deviceSeed, "", privacyUUID(p.sessionSeed), p.jsonMetadata)
		p.body, err = sjson.SetBytes(p.body, "metadata.user_id", p.ingressUserID)
		if err != nil {
			return nil, privacyInputError("invalid_metadata")
		}
	}
	for _, field := range []struct {
		name, domain string
		target       *string
	}{
		{"X-Claude-Code-Agent-Id", "agent", &p.agentSeed},
		{"X-Claude-Code-Parent-Agent-Id", "agent", &p.parentSeed},
		{"X-Claude-Code-Prompt-Id", "prompt", &p.promptSeed},
	} {
		if value := headers.Get(field.name); value != "" {
			if session == "" || len(value) > 256 {
				return nil, privacyInputError("invalid_correlation")
			}
			*field.target = s.digest(field.domain, p.sessionSeed, value)
			p.headers.Set(field.name, privacyUUID(*field.target))
		}
	}
	if headers.Get("X-Claude-Code-Parent-Agent-Id") != "" && p.agentSeed == "" {
		return nil, privacyInputError("invalid_correlation")
	}
	if headers.Get("X-Client-Request-Id") != "" {
		p.headers.Set("X-Client-Request-Id", uuid.NewString())
	}
	for _, name := range []string{"Anthropic-Version", "Anthropic-Beta"} {
		if value := headers.Get(name); value != "" {
			if name == "Anthropic-Version" {
				if _, err := time.Parse("2006-01-02", value); err != nil {
					return nil, privacyInputError("invalid_protocol_header")
				}
			} else {
				for _, token := range strings.Split(value, ",") {
					if !privacyBetaToken.MatchString(strings.TrimSpace(token)) {
						return nil, privacyInputError("invalid_protocol_header")
					}
				}
			}
			p.headers.Set(name, value)
		}
	}
	for _, name := range []string{"X-Stainless-Retry-Count", "X-Stainless-Timeout"} {
		if value := headers.Get(name); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 86400 {
				return nil, privacyInputError("invalid_diagnostic_header")
			}
			p.headers.Set(name, strconv.Itoa(n))
		}
	}
	for name, allowed := range map[string]string{
		"X-Stainless-Helper-Method":       "stream",
		"X-Claude-Code-Request-Class":     "main,subagent,workflow,compaction,auxiliary",
		"X-Claude-Code-Agent-Type":        "Explore,Plan,general-purpose,custom,teammate,fork",
		"X-Claude-Code-Compaction":        "auto,manual,reactive",
		"X-Claude-Code-Context-Compacted": "auto,manual,reactive",
	} {
		if value := headers.Get(name); value != "" && containsPrivacyToken(allowed, value) {
			p.headers.Set(name, value)
		}
	}
	return p, nil
}

func containsPrivacyToken(list, value string) bool {
	for _, item := range strings.Split(list, ",") {
		if strings.TrimSpace(item) == value {
			return true
		}
	}
	return false
}

var privacyBetaToken = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

// Apply reconstructs the final outgoing headers after all legacy defaults and
// overrides. The selected upstream credential is the only preserved header.
func (p *PreparedClaudePrivacy) Apply(account *Account, req *http.Request, body []byte) ([]byte, error) {
	if req == nil || req.Method != http.MethodPost || account == nil || account.ID <= 0 ||
		account.Platform != PlatformAnthropic || !account.IsOAuth() {
		return nil, privacyConfigError("unsupported_upstream")
	}
	if err := validatePrivacyJSON(body); err != nil {
		return nil, err
	}
	if !gjson.ParseBytes(body).IsObject() {
		return nil, privacyConfigError("body_identity_changed")
	}
	metadata := gjson.GetBytes(body, "metadata")
	uid := metadata.Get("user_id")
	if uid.Exists() != p.hasMetadata || (p.hasMetadata && (uid.Type != gjson.String || uid.String() != p.ingressUserID)) {
		return nil, privacyConfigError("body_identity_changed")
	}
	if metadata.Exists() && metadata.Raw != "null" {
		if !metadata.IsObject() {
			return nil, privacyConfigError("body_identity_changed")
		}
		for name := range metadata.Map() {
			if name != "user_id" {
				return nil, privacyConfigError("body_identity_changed")
			}
		}
	}
	if guards := gjson.GetBytes(body, "safeguards"); guards.Exists() && guards.Raw != "null" && (!guards.IsArray() || len(guards.Array()) > 0) {
		return nil, privacyInputError("incompatible_classifier_context")
	}
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) <= 7 {
		return nil, privacyConfigError("upstream_auth_missing")
	}
	accountID := strconv.FormatInt(account.ID, 10)
	wire := func(domain, seed string) string { return p.owner.digest(domain, accountID, seed) }
	headers := p.headers.Clone()
	if headers.Get("X-Claude-Code-Session-Id") != "" {
		headers.Set("X-Claude-Code-Session-Id", privacyUUID(wire("wire-session", p.sessionSeed)))
	}
	for _, field := range []struct{ name, domain, seed string }{
		{"X-Claude-Code-Agent-Id", "wire-agent", p.agentSeed},
		{"X-Claude-Code-Parent-Agent-Id", "wire-agent", p.parentSeed},
		{"X-Claude-Code-Prompt-Id", "wire-prompt", p.promptSeed},
	} {
		if field.seed != "" {
			headers.Set(field.name, privacyUUID(wire(field.domain, field.seed)))
		}
	}
	if p.hasMetadata {
		accountUUID, err := uuid.Parse(account.GetExtraString("account_uuid"))
		if err != nil || accountUUID == uuid.Nil {
			return nil, privacyConfigError("upstream_account_uuid_missing")
		}
		uid := formatPrivacyUserID(wire("wire-device", p.deviceSeed), accountUUID.String(), privacyUUID(wire("wire-session", p.sessionSeed)), p.jsonMetadata)
		body, err = sjson.SetBytes(body, "metadata.user_id", uid)
		if err != nil {
			return nil, privacyConfigError("output_validation_failed")
		}
		if headers.Get("X-Claude-Code-Session-Id") != "" && ParseMetadataUserID(uid).SessionID != headers.Get("X-Claude-Code-Session-Id") {
			return nil, privacyConfigError("output_validation_failed")
		}
	}
	if p.countTokens {
		body = sanitizeCountTokensRequestBody(body)
	}
	beta := headers.Get("Anthropic-Beta")
	if !containsPrivacyToken(beta, claude.BetaOAuth) {
		if beta != "" {
			beta += ","
		}
		beta += claude.BetaOAuth
	}
	headers.Set("Anthropic-Beta", beta)
	if headers.Get("Anthropic-Version") == "" {
		headers.Set("Anthropic-Version", "2023-06-01")
	}
	headers.Set("Authorization", auth)
	headers.Set("Content-Type", "application/json")
	headers.Set("Accept", "application/json")
	headers.Set("X-App", "cli")
	headers.Set("Anthropic-Dangerous-Direct-Browser-Access", "true")
	req.Header = headers
	// Host and trailers live outside Header in net/http. Never retain a
	// caller-supplied override; the selected URL and fixed body length win.
	req.Host = ""
	req.Trailer = nil
	req.TransferEncoding = nil
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	snapshot := bytes.Clone(body)
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(snapshot)), nil }
	return body, nil
}

func (s *GatewayService) buildClaudePrivateRequest(ctx context.Context, account *Account, body []byte, token, tokenType, modelID string, countTokens bool) (*http.Request, []byte, error) {
	if err := ValidateClaudePrivacyTarget(ctx, account); err != nil {
		return nil, nil, err
	}
	p := preparedClaudePrivacy(ctx)
	if p.countTokens != countTokens || tokenType != "oauth" {
		return nil, nil, privacyConfigError("operation_mismatch")
	}
	// Preserve admin block/filter policies without silently removing native
	// capabilities. A conflicting filter requires an explicit policy change.
	policy := s.evaluateBetaPolicy(ctx, p.headers.Get("Anthropic-Beta"), account, modelID)
	if policy.blockErr != nil {
		return nil, nil, policy.blockErr
	}
	for _, beta := range strings.Split(p.headers.Get("Anthropic-Beta")+","+claude.BetaOAuth, ",") {
		if _, filtered := policy.filterSet[strings.TrimSpace(beta)]; filtered {
			return nil, nil, privacyConfigError("incompatible_beta_policy")
		}
	}
	path, targetURL := "/v1/messages", claudeAPIURL
	if countTokens {
		path, targetURL = "/v1/messages/count_tokens", claudeAPICountTokensURL
	}
	if account.IsCustomBaseURLEnabled() {
		base, err := s.validateUpstreamBaseURL(account.GetCustomBaseURL())
		if err != nil {
			return nil, nil, privacyConfigError("invalid_upstream_url")
		}
		targetURL = s.buildCustomRelayURL(base, path, account)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, nil)
	if err != nil {
		return nil, nil, privacyConfigError("invalid_upstream_url")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	body, err = p.Apply(account, req, body)
	if err != nil {
		return nil, nil, err
	}
	return req, body, nil
}

// Used only for diagnostics, not for altering the response delivered to a client.
func claudePrivacyLogText(ctx context.Context, text string) string {
	if ClaudeIdentityPrivacyEnabled(ctx) {
		return "[omitted: identity privacy]"
	}
	return text
}
