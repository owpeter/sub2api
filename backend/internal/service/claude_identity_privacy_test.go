package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const privacyTestSession = "9db8f264-b111-4cf4-b4d4-e837213c9971"
const privacyTestAccountUUID = "92a89588-41a3-486b-a188-ab9e55efdf61"

func privacyTestConfig() config.ClaudeIdentityPrivacyConfig {
	return config.ClaudeIdentityPrivacyConfig{Key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32)), Namespace: "privacy-test"}
}

func privacyTestInput(t *testing.T) ClaudePrivacyInput {
	t.Helper()
	uid := formatPrivacyUserID(strings.Repeat("a", 64), "local-account-marker", privacyTestSession, true)
	body := []byte(`{"model":"claude-sonnet-4-6","max_tokens":100,"stream":false,"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.300.abc; cc_entrypoint=sdk-cli;"},{"type":"text","text":"Today's date is 2026-10-14.","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"hello"}],"tools":[{"name":"Read","description":"read","input_schema":{"type":"object","properties":{}}}],"metadata":{}}`)
	body, err := sjson.SetBytes(body, "metadata.user_id", uid)
	require.NoError(t, err)
	h := http.Header{}
	h.Set("User-Agent", "claude-cli/2.1.300 (external, sdk-cli) local-ua-marker")
	h.Set("X-Claude-Code-Session-Id", privacyTestSession)
	h.Set("X-Stainless-Os", "local-os-marker")
	h.Set("X-Stainless-Runtime-Version", "local-runtime-marker")
	h.Set("X-Claude-Code-Prev-Tool-Durations", "local-tool-marker=12")
	h.Set("Forwarded", "for=local-ip-marker")
	h.Set("X-Forwarded-For", "local-ip-marker")
	h.Set("X-Real-IP", "local-ip-marker")
	h.Set("Cookie", "local-cookie-marker")
	h.Set("X-Arbitrary", "local-custom-marker")
	h.Set("Authorization", "Bearer local-token-marker")
	h.Set("X-Api-Key", "local-key-marker")
	h.Set("Anthropic-Beta", "claude-code-20250219,future-capability-2099-01-01")
	h.Set("Anthropic-Version", "2023-06-01")
	return ClaudePrivacyInput{GroupID: 7, APIKeyID: 19, Body: body, Headers: h}
}

func privacyTestAccount() *Account {
	a := newAnthropicOAuthAccountForPartialUsageTest()
	a.Extra = map[string]any{"account_uuid": privacyTestAccountUUID, "session_id_masking_enabled": true}
	return a
}

func preparePrivacyTest(t *testing.T, input ClaudePrivacyInput) *PreparedClaudePrivacy {
	t.Helper()
	s, err := NewClaudeIdentityPrivacy(privacyTestConfig())
	require.NoError(t, err)
	p, err := s.Prepare(input)
	require.NoError(t, err)
	return p
}

func applyPrivacyTest(t *testing.T, p *PreparedClaudePrivacy, a *Account) (*http.Request, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	// Deliberately contaminated final headers: Apply must be authoritative.
	req.Header = privacyTestInput(t).Headers
	req.Header.Set("Authorization", "Bearer selected-upstream-token")
	req.Header.Set("X-Stainless-Arch", "legacy-default-arch")
	req.Host = "local-host-marker"
	req.Trailer = http.Header{"X-Local-Trailer": {"local-trailer-marker"}}
	req.TransferEncoding = []string{"chunked"}
	body, err := p.Apply(a, req, p.IngressBody())
	require.NoError(t, err)
	return req, body
}

func assertPrivateWire(t *testing.T, req *http.Request, body []byte) *ParsedUserID {
	t.Helper()
	h, err := json.Marshal(req.Header)
	require.NoError(t, err)
	require.Empty(t, req.Host)
	require.Empty(t, req.Trailer)
	require.Empty(t, req.TransferEncoding)
	for _, marker := range []string{"local-", strings.Repeat("a", 64), privacyTestSession, "legacy-default"} {
		require.NotContains(t, string(h), marker)
		require.NotContains(t, string(body), marker)
	}
	for _, name := range []string{"X-Stainless-Os", "X-Stainless-Arch", "X-Stainless-Runtime", "X-Stainless-Runtime-Version", "X-Stainless-Lang", "X-Stainless-Package-Version", "Cookie", "Forwarded", "X-Forwarded-For", "X-Real-IP", "X-Arbitrary", "X-Claude-Code-Prev-Tool-Durations", "X-Api-Key"} {
		require.Empty(t, req.Header.Get(name), name)
	}
	id := ParseMetadataUserID(gjson.GetBytes(body, "metadata.user_id").String())
	require.NotNil(t, id)
	require.Len(t, id.DeviceID, 64)
	_, err = uuid.Parse(id.SessionID)
	require.NoError(t, err)
	require.Equal(t, privacyTestAccountUUID, id.AccountUUID)
	require.Equal(t, id.SessionID, req.Header.Get("X-Claude-Code-Session-Id"))
	require.Equal(t, int64(len(body)), req.ContentLength)
	reread, err := req.GetBody()
	require.NoError(t, err)
	b, err := io.ReadAll(reread)
	require.NoError(t, err)
	_ = reread.Close()
	require.Equal(t, body, b)
	return id
}

func TestClaudePrivacyStableScopedIdentity(t *testing.T) {
	in := privacyTestInput(t)
	p := preparePrivacyTest(t, in)
	req, body := applyPrivacyTest(t, p, privacyTestAccount())
	base := assertPrivateWire(t, req, body)
	require.Equal(t, "claude-cli/2.1.300 (external, sdk-cli)", req.UserAgent())
	require.Empty(t, req.Header.Get("X-Client-Request-Id"))
	require.Empty(t, req.Header.Get("X-Stainless-Helper-Method"))
	require.Contains(t, req.Header.Get("Anthropic-Beta"), "future-capability-2099-01-01")
	require.Contains(t, req.Header.Get("Anthropic-Beta"), claude.BetaOAuth)
	for _, path := range []string{"system", "messages", "tools", "stream", "max_tokens"} {
		require.Equal(t, gjson.GetBytes(in.Body, path).Raw, gjson.GetBytes(body, path).Raw, path)
	}
	// Different instances, multi-turn input and concurrent workers share no state.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other := in
			other.Body, _ = sjson.SetBytes(in.Body, "messages.0.content", "another prompt")
			otherP := preparePrivacyTest(t, other)
			_, otherBody := applyPrivacyTest(t, otherP, privacyTestAccount())
			require.Equal(t, base, ParseMetadataUserID(gjson.GetBytes(otherBody, "metadata.user_id").String()))
			require.Equal(t, p.routingKey, otherP.routingKey)
		}()
	}
	wg.Wait()
	for _, dimension := range []string{"group", "key", "session", "upstream", "namespace", "secret"} {
		t.Run(dimension, func(t *testing.T) {
			input := privacyTestInput(t)
			cfg, a := privacyTestConfig(), privacyTestAccount()
			switch dimension {
			case "group":
				input.GroupID++
			case "key":
				input.APIKeyID++
			case "session":
				sid := uuid.NewString()
				input.Headers.Set("X-Claude-Code-Session-Id", sid)
				input.Body, _ = sjson.SetBytes(input.Body, "metadata.user_id", formatPrivacyUserID(strings.Repeat("a", 64), "", sid, true))
			case "upstream":
				a.ID++
			case "namespace":
				cfg.Namespace += "-other"
			case "secret":
				cfg.Key = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{43}, 32))
			}
			engine, err := NewClaudeIdentityPrivacy(cfg)
			require.NoError(t, err)
			other, err := engine.Prepare(input)
			require.NoError(t, err)
			_, b := applyPrivacyTest(t, other, a)
			id := ParseMetadataUserID(gjson.GetBytes(b, "metadata.user_id").String())
			require.NotEqual(t, base.SessionID, id.SessionID)
			if dimension == "session" {
				require.Equal(t, base.DeviceID, id.DeviceID)
			} else {
				require.NotEqual(t, base.DeviceID, id.DeviceID)
			}
			if dimension == "upstream" {
				require.Equal(t, p.routingKey, other.routingKey)
			} else {
				require.NotEqual(t, p.routingKey, other.routingKey)
			}
		})
	}
	// Changing the downstream login account alone must not change pseudonyms.
	in.Body, _ = sjson.SetBytes(in.Body, "metadata.user_id", formatPrivacyUserID(strings.Repeat("a", 64), "other-login", privacyTestSession, true))
	_, b := applyPrivacyTest(t, preparePrivacyTest(t, in), privacyTestAccount())
	require.Equal(t, base, ParseMetadataUserID(gjson.GetBytes(b, "metadata.user_id").String()))
}

func TestClaudePrivacyCorrelationAndHelpers(t *testing.T) {
	in := privacyTestInput(t)
	in.Headers.Set("X-Claude-Code-Agent-Id", "parent")
	in.Headers.Set("X-Claude-Code-Prompt-Id", "prompt-1")
	in.Headers.Set("X-Client-Request-Id", "local-request-marker")
	p := preparePrivacyTest(t, in)
	req, body := applyPrivacyTest(t, p, privacyTestAccount())
	retry, retried := applyPrivacyTest(t, p, privacyTestAccount())
	require.Equal(t, body, retried)
	require.Equal(t, req.Header, retry.Header)
	require.NotEmpty(t, req.Header.Get("X-Client-Request-Id"))
	in.Headers.Set("X-Claude-Code-Agent-Id", "child")
	in.Headers.Set("X-Claude-Code-Parent-Agent-Id", "parent")
	child, _ := applyPrivacyTest(t, preparePrivacyTest(t, in), privacyTestAccount())
	require.Equal(t, req.Header.Get("X-Claude-Code-Agent-Id"), child.Header.Get("X-Claude-Code-Parent-Agent-Id"))
	require.Equal(t, req.Header.Get("X-Claude-Code-Prompt-Id"), child.Header.Get("X-Claude-Code-Prompt-Id"))
	in.Headers.Set("X-Claude-Code-Prompt-Id", "prompt-2")
	next, _ := applyPrivacyTest(t, preparePrivacyTest(t, in), privacyTestAccount())
	require.NotEqual(t, child.Header.Get("X-Claude-Code-Prompt-Id"), next.Header.Get("X-Claude-Code-Prompt-Id"))
	for _, count := range []bool{false, true} {
		helper := ClaudePrivacyInput{GroupID: 7, APIKeyID: 19, CountTokens: count, Body: []byte(`{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"probe"}]}`), Headers: http.Header{"User-Agent": {"claude-cli/2.1.300 (external, cli)"}}}
		hreq, hbody := applyPrivacyTest(t, preparePrivacyTest(t, helper), privacyTestAccount())
		require.Empty(t, hreq.Header.Get("X-Claude-Code-Session-Id"))
		require.False(t, gjson.GetBytes(hbody, "metadata").Exists())
	}
	legacy := privacyTestInput(t)
	legacy.Body, _ = sjson.SetBytes(legacy.Body, "metadata.user_id", formatPrivacyUserID(strings.Repeat("a", 64), "", privacyTestSession, false))
	_, lb := applyPrivacyTest(t, preparePrivacyTest(t, legacy), privacyTestAccount())
	require.False(t, ParseMetadataUserID(gjson.GetBytes(lb, "metadata.user_id").String()).IsNewFormat)
}

func TestClaudePrivacyRejectsAmbiguousAndUnsupportedInputs(t *testing.T) {
	engine, err := NewClaudeIdentityPrivacy(privacyTestConfig())
	require.NoError(t, err)
	cases := map[string]func(*ClaudePrivacyInput){
		"duplicate JSON": func(in *ClaudePrivacyInput) {
			in.Body = []byte(`{"metadata":{},"metadata":{"user_id":"local-marker"}}`)
		},
		"duplicate nested identity": func(in *ClaudePrivacyInput) {
			in.Body, _ = sjson.SetBytes(in.Body, "metadata.user_id", `{"device_id":"local-marker","device_id":"other","account_uuid":"","session_id":"`+privacyTestSession+`"}`)
		},
		"unknown metadata": func(in *ClaudePrivacyInput) { in.Body, _ = sjson.SetBytes(in.Body, "metadata.email", "local-marker") },
		"unknown identity": func(in *ClaudePrivacyInput) { in.Body, _ = sjson.SetBytes(in.Body, "metadata.user_id", "local-marker") },
		"non-string identity": func(in *ClaudePrivacyInput) {
			in.Body, _ = sjson.SetBytes(in.Body, "metadata.user_id", map[string]string{"device_id": "local-marker"})
		},
		"session mismatch": func(in *ClaudePrivacyInput) { in.Headers.Set("X-Claude-Code-Session-Id", uuid.NewString()) },
		"invalid session":  func(in *ClaudePrivacyInput) { in.Headers.Set("X-Claude-Code-Session-Id", "local-marker") },
		"duplicate header": func(in *ClaudePrivacyInput) { in.Headers.Add("X-Claude-Code-Session-Id", privacyTestSession) },
		"duplicate case":   func(in *ClaudePrivacyInput) { in.Headers["x-claude-code-session-id"] = []string{privacyTestSession} },
		"newline":          func(in *ClaudePrivacyInput) { in.Headers.Set("X-Stainless-Os", "local-marker\r\nfoo: bar") },
		"negative retry":   func(in *ClaudePrivacyInput) { in.Headers.Set("X-Stainless-Retry-Count", "-1") },
		"unknown UA":       func(in *ClaudePrivacyInput) { in.Headers.Set("User-Agent", "local-marker") },
		"missing session": func(in *ClaudePrivacyInput) {
			in.Body, _ = sjson.DeleteBytes(in.Body, "metadata")
			in.Headers.Del("X-Claude-Code-Session-Id")
		},
		"parent without agent": func(in *ClaudePrivacyInput) { in.Headers.Set("X-Claude-Code-Parent-Agent-Id", "local-marker") },
		"safeguards": func(in *ClaudePrivacyInput) {
			in.Body, _ = sjson.SetBytes(in.Body, "safeguards", []any{map[string]any{"classifier_context": map[string]string{"user_identity": "local-marker"}}})
		},
		"unsupported safeguard": func(in *ClaudePrivacyInput) {
			in.Body, _ = sjson.SetBytes(in.Body, "safeguards", []any{map[string]string{"type": "future"}})
		},
		"invalid JSON": func(in *ClaudePrivacyInput) { in.Body = []byte(`{"local-marker":`) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := privacyTestInput(t)
			mutate(&in)
			p, err := engine.Prepare(in)
			require.Error(t, err)
			require.Nil(t, p)
			require.NotContains(t, err.Error(), "local-marker")
		})
	}
	for _, cfg := range []config.ClaudeIdentityPrivacyConfig{{}, {Key: privacyTestConfig().Key}, {Key: "bad", Namespace: "test"}} {
		_, err := NewClaudeIdentityPrivacy(cfg)
		require.Error(t, err)
	}
	p := preparePrivacyTest(t, privacyTestInput(t))
	req, b := applyPrivacyTest(t, p, privacyTestAccount())
	_, err = p.Apply(privacyTestAccount(), req, b)
	require.EqualError(t, err, "privacy_body_identity_changed")
	for _, a := range []*Account{nil, {ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth}, {ID: 1, Platform: PlatformAnthropic, Type: AccountTypeAPIKey}, {ID: 1, Platform: PlatformAnthropic, Type: AccountTypeOAuth}} {
		_, err = p.Apply(a, req, p.IngressBody())
		require.Error(t, err)
	}
	require.NoError(t, ValidateClaudePrivacyTarget(context.Background(), nil), "disabled mode keeps legacy behavior")
	require.Error(t, ValidateClaudePrivacyTarget(MarkClaudeIdentityPrivacy(context.Background()), privacyTestAccount()))
}

func TestClaudePrivacyCapturedRequests(t *testing.T) {
	data, err := os.ReadFile("testdata/claude_identity_privacy/cli-2.1.300.json")
	require.NoError(t, err)
	var samples []struct {
		Name    string          `json:"name"`
		Reject  bool            `json:"reject_safeguards"`
		Headers http.Header     `json:"headers"`
		Body    json.RawMessage `json:"body"`
	}
	require.NoError(t, json.Unmarshal(data, &samples))
	require.Len(t, samples, 14)
	engine, err := NewClaudeIdentityPrivacy(privacyTestConfig())
	require.NoError(t, err)
	svc := &GatewayService{cfg: &config.Config{}, identityService: &IdentityService{}}
	for _, sample := range samples {
		t.Run(sample.Name, func(t *testing.T) {
			for _, count := range []bool{false, true} {
				p, err := engine.Prepare(ClaudePrivacyInput{GroupID: 7, APIKeyID: 19, Body: sample.Body, Headers: sample.Headers, CountTokens: count})
				if sample.Reject {
					require.EqualError(t, err, "privacy_incompatible_classifier_context")
					continue
				}
				require.NoError(t, err)
				ctx := WithPreparedClaudePrivacy(context.Background(), p)
				var req *http.Request
				var b []byte
				if count {
					req, b, err = svc.buildCountTokensRequest(ctx, nil, privacyTestAccount(), p.IngressBody(), "dummy", "oauth", "claude-sonnet-4-6", true)
				} else {
					req, b, err = svc.buildUpstreamRequest(ctx, nil, privacyTestAccount(), p.IngressBody(), "dummy", "oauth", "claude-sonnet-4-6", true, true)
				}
				require.NoError(t, err)
				for _, path := range []string{"system", "messages", "tools", "thinking", "context_management"} {
					require.Equal(t, gjson.GetBytes(sample.Body, path).Raw, gjson.GetBytes(b, path).Raw, path)
				}
				before := ParseMetadataUserID(gjson.GetBytes(sample.Body, "metadata.user_id").String())
				after := ParseMetadataUserID(gjson.GetBytes(b, "metadata.user_id").String())
				require.NotEqual(t, before.DeviceID, after.DeviceID)
				require.NotEqual(t, before.SessionID, after.SessionID)
				require.Equal(t, after.SessionID, req.Header.Get("X-Claude-Code-Session-Id"))
				require.Empty(t, req.Header.Get("X-Client-Request-Id"))
				require.Empty(t, req.Header.Get("X-Stainless-Helper-Method"))
				require.Contains(t, req.UserAgent(), "2.1.300")
				if count {
					require.Contains(t, req.URL.Path, "count_tokens")
					require.False(t, gjson.GetBytes(b, "stream").Exists())
				}
			}
		})
	}
}

func TestClaudePrivacyFinalHTTPBothEndpointsAndFailover(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, count := range []bool{false, true} {
		t.Run(map[bool]string{false: "messages", true: "count_tokens"}[count], func(t *testing.T) {
			in := privacyTestInput(t)
			in.CountTokens = count
			p := preparePrivacyTest(t, in)
			ctx := WithPreparedClaudePrivacy(context.Background(), p)
			upstream := &anthropicHTTPUpstreamRecorder{}
			svc := newForwardPartialUsageServiceForTest(upstream)
			// Any use of the old fingerprint cache would panic on this empty service.
			svc.identityService = &IdentityService{}
			var firstID *ParsedUserID
			for attempt := 0; attempt < 3; attempt++ {
				c, _ := gin.CreateTestContext(httptest.NewRecorder())
				c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil).WithContext(ctx)
				c.Request.Header = p.IngressHeaders()
				parsed, err := ParseGatewayRequest(NewRequestBodyRef(p.IngressBody()), PlatformAnthropic)
				require.NoError(t, err)
				a := privacyTestAccount()
				if attempt == 2 {
					a.ID++
				}
				response := `{"id":"msg_test","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"OK"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":1}}`
				if count {
					response = `{"input_tokens":10}`
				}
				upstream.resp = &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response))}
				if count {
					err = svc.ForwardCountTokens(ctx, c, a, parsed)
				} else {
					_, err = svc.Forward(ctx, c, a, parsed)
				}
				require.NoError(t, err)
				id := assertPrivateWire(t, upstream.lastReq, upstream.lastBody)
				if firstID == nil {
					firstID = id
				} else if attempt == 1 {
					require.Equal(t, firstID, id)
				} else {
					require.NotEqual(t, firstID.SessionID, id.SessionID)
				}
				for _, path := range []string{"system", "messages", "tools"} {
					require.JSONEq(t, gjson.GetBytes(in.Body, path).Raw, gjson.GetBytes(upstream.lastBody, path).Raw, path)
				}
			}
		})
	}
}

type privacySettingsRepo struct {
	*gatewayTTLSettingRepo
	failure bool
}

func (r *privacySettingsRepo) GetMultiple(ctx context.Context, keys []string) (map[string]string, error) {
	if r.failure {
		return nil, errors.New("local-secret-error-marker")
	}
	return r.gatewayTTLSettingRepo.GetMultiple(ctx, keys)
}

type privacyGroupReader struct{ groups map[int64]*Group }

func (r privacyGroupReader) GetByID(_ context.Context, id int64) (*Group, error) {
	return r.groups[id], nil
}

func TestClaudePrivacySettingsFailClosedAndRecoverable(t *testing.T) {
	ctx := context.Background()
	repo := &privacySettingsRepo{gatewayTTLSettingRepo: &gatewayTTLSettingRepo{data: map[string]string{}}}
	s := NewSettingService(repo, &config.Config{})
	defaults, err := s.GetClaudeIdentityPrivacySettings(ctx)
	require.NoError(t, err)
	require.Empty(t, defaults.EnabledGroupIDs)
	on := &ClaudeCodeIdentityPrivacySettings{Version: 1, EnabledGroupIDs: []int64{7}}
	_, err = s.claudePrivacySettingUpdate(ctx, on)
	require.EqualError(t, err, "privacy_key_not_configured")
	s.cfg.Gateway.ClaudeIdentityPrivacy = privacyTestConfig()
	s.SetDefaultSubscriptionGroupReader(privacyGroupReader{map[int64]*Group{7: {ID: 7, Platform: PlatformAnthropic}, 8: {ID: 8, Platform: PlatformOpenAI}}})
	raw, err := s.claudePrivacySettingUpdate(ctx, on)
	require.NoError(t, err)
	_, err = s.claudePrivacySettingUpdate(ctx, &ClaudeCodeIdentityPrivacySettings{Version: 1, EnabledGroupIDs: []int64{8}})
	require.EqualError(t, err, "privacy_unsupported_group")
	repo.data[SettingKeyClaudeCodeIdentityPrivacy] = raw
	s.claudePrivacyCache.Store(nil)
	loaded, err := s.GetClaudeIdentityPrivacySettings(ctx)
	require.NoError(t, err)
	require.True(t, loaded.Enabled(&on.EnabledGroupIDs[0]))
	loaded.EnabledGroupIDs[0] = 999
	again, err := s.GetClaudeIdentityPrivacySettings(ctx)
	require.NoError(t, err)
	require.Equal(t, []int64{7}, again.EnabledGroupIDs)
	repo.failure = true
	s.claudePrivacyCache.Store(&cachedClaudePrivacySettings{settings: on, expires: time.Now().Add(-time.Second)})
	loaded, err = s.GetClaudeIdentityPrivacySettings(ctx)
	require.Nil(t, loaded)
	require.EqualError(t, err, "privacy_settings_unavailable")
	repo.failure = false
	repo.data[SettingKeyClaudeCodeIdentityPrivacy] = `{"version":99}`
	s.claudePrivacyCache.Store(nil)
	_, err = s.GetClaudeIdentityPrivacySettings(ctx)
	require.Error(t, err)
	admin, err := s.GetAllSettings(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, admin.ClaudeCodeIdentityPrivacy.Version)
	admin.ClaudeCodeIdentityPrivacy = nil
	updates, err := s.buildSystemSettingsUpdates(ctx, admin)
	require.NoError(t, err)
	_, exists := updates[SettingKeyClaudeCodeIdentityPrivacy]
	require.False(t, exists)
	secretFree, err := json.Marshal(s.cfg)
	require.NoError(t, err)
	require.NotContains(t, string(secretFree), privacyTestConfig().Key)
	for _, bad := range []string{`null`, ` null `, `[]`, `{"version":2}`, `{"version":1,"enabled_group_ids":[7,7]}`, `{"version":1,"enabled_group_ids":[-1]}`, `{"version":1,"enabled_group_ids":[],"key":"secret"}`, `{"version":1,"version":1}`} {
		_, err := parseClaudePrivacySettings(bad)
		require.Error(t, err, bad)
	}
}

func TestClaudePrivacyOpsAndErrorControlFlow(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil).WithContext(MarkClaudeIdentityPrivacy(context.Background()))
	setOpsUpstreamError(c, 429, "local-error-marker", "local-detail-marker")
	appendOpsUpstreamError(c, OpsUpstreamErrorEvent{UpstreamStatusCode: 429, Message: "local-error-marker", Detail: "local-detail-marker", UpstreamResponseBody: "local-body-marker", UpstreamRequestID: "local-request-marker"})
	markOpsStreamError(c, OpsStreamError{Message: "local-stream-marker"})
	for _, key := range []string{OpsUpstreamErrorMessageKey, OpsUpstreamErrorDetailKey, OpsUpstreamErrorsKey, OpsStreamErrorKey} {
		value, _ := c.Get(key)
		b, err := json.Marshal(value)
		require.NoError(t, err)
		require.NotContains(t, string(b), "local-")
	}
	failover := &UpstreamFailoverError{StatusCode: 429, ResponseBody: []byte("local-body-marker")}
	err := claudePrivacySafeError(c.Request.Context(), failover)
	require.EqualError(t, err, "privacy_forward_error")
	var typed *UpstreamFailoverError
	require.True(t, errors.As(err, &typed))
	require.Equal(t, 429, typed.StatusCode)
}
