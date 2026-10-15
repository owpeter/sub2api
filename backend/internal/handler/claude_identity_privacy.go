package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	pkghttputil "github.com/Wei-Shaw/sub2api/internal/pkg/httputil"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type claudePrivacyIngress struct {
	engine            *service.ClaudeIdentityPrivacy
	headers           http.Header
	groupID, apiKeyID int64
}

const claudePrivacyCheckedKey = "claude_identity_privacy_checked"

// Run after authentication and before platform routing/model-body inspection.
// Direct handler callers retain the same checks below. Only Messages protocol
// endpoints participate; other APIs are outside this opt-in policy's scope.
func (h *GatewayHandler) ClaudeIdentityPrivacyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h == nil || c.Request == nil || c.Request.Method != http.MethodPost ||
			(!strings.HasSuffix(c.Request.URL.Path, "/messages") && !strings.HasSuffix(c.Request.URL.Path, "/messages/count_tokens")) {
			c.Next()
			return
		}
		key, ok := middleware2.GetAPIKeyFromContext(c)
		if !ok || key == nil {
			c.Next()
			return
		}
		stage, ok := h.beginClaudePrivacy(c, key)
		if !ok {
			c.Abort()
			return
		}
		if stage == nil {
			c.Next()
			return
		}
		body, err := readLenientJSONRequestBodyWithPrealloc(c.Request, h.cfg)
		if err != nil {
			status := http.StatusBadRequest
			if _, tooLarge := extractMaxBytesError(err); tooLarge {
				status = http.StatusRequestEntityTooLarge
			}
			h.claudePrivacyError(c, &service.ClaudePrivacyError{Status: status, Code: "privacy_invalid_body"})
			c.Request.Body, c.Request.GetBody = http.NoBody, nil
			c.Abort()
			return
		}
		if _, ok := h.prepareClaudePrivacy(c, stage, body, strings.HasSuffix(c.Request.URL.Path, "/count_tokens")); !ok {
			c.Abort()
			return
		}
		c.Next()
	}
}

// Runs immediately after authentication, before body parsing, logging or audit.
func (h *GatewayHandler) beginClaudePrivacy(c *gin.Context, key *service.APIKey) (*claudePrivacyIngress, bool) {
	if c.GetBool(claudePrivacyCheckedKey) {
		return nil, true
	}
	if h.settingService == nil {
		return nil, true
	}
	settings, err := h.settingService.GetClaudeIdentityPrivacySettings(c.Request.Context())
	c.Set(claudePrivacyCheckedKey, true)
	if err == nil && !settings.Enabled(key.GroupID) {
		return nil, true
	}
	ip.SnapshotClientIPs(c)
	originalHeaders := c.Request.Header.Clone()
	ctx := service.MarkClaudeIdentityPrivacy(c.Request.Context())
	requestID := uuid.NewString()
	ctx = context.WithValue(ctx, ctxkey.RequestID, requestID)
	ctx = context.WithValue(ctx, ctxkey.ClientRequestID, requestID)
	// Replace the earlier logger: it may already contain a client-supplied ID.
	ctx = logger.IntoContext(ctx, logger.With(zap.String("request_id", requestID), zap.String("component", "http")))
	c.Request = c.Request.WithContext(ctx)
	c.Header("X-Request-ID", requestID)
	c.Header("X-Client-Request-ID", requestID)
	// Until Prepare succeeds, diagnostics see no unvalidated client headers.
	c.Request.Header = make(http.Header)
	c.Request.Header.Set("Content-Type", "application/json")
	if err != nil {
		h.claudePrivacyError(c, err)
		return nil, false
	}
	// The reader still needs the transport encoding to decode compressed JSON.
	// Keep only a validated token until Prepare replaces the decoded body.
	encodingSeen := false
	for name, values := range originalHeaders {
		if !strings.EqualFold(name, "Content-Encoding") {
			continue
		}
		if encodingSeen || len(values) != 1 {
			h.claudePrivacyError(c, &service.ClaudePrivacyError{Status: 400, Code: "privacy_invalid_content_encoding"})
			return nil, false
		}
		encodingSeen = true
		encoding := strings.ToLower(strings.TrimSpace(values[0]))
		switch encoding {
		case "", "identity", "gzip", "x-gzip", "deflate", "zstd":
			if encoding != "" {
				c.Request.Header.Set("Content-Encoding", encoding)
			}
		default:
			h.claudePrivacyError(c, &service.ClaudePrivacyError{Status: 400, Code: "privacy_invalid_content_encoding"})
			return nil, false
		}
	}
	if key.GroupID == nil || key.Group == nil || key.Group.Platform != service.PlatformAnthropic {
		h.claudePrivacyError(c, &service.ClaudePrivacyError{Status: 503, Code: "privacy_unsupported_group"})
		return nil, false
	}
	if platform, forced := middleware2.GetForcePlatformFromContext(c); forced && platform != service.PlatformAnthropic {
		h.claudePrivacyError(c, &service.ClaudePrivacyError{Status: 503, Code: "privacy_unsupported_upstream"})
		return nil, false
	}
	var cfg config.ClaudeIdentityPrivacyConfig
	if h.cfg != nil {
		cfg = h.cfg.Gateway.ClaudeIdentityPrivacy
	}
	engine, err := service.NewClaudeIdentityPrivacy(cfg)
	if err != nil {
		h.claudePrivacyError(c, err)
		return nil, false
	}
	return &claudePrivacyIngress{engine: engine, headers: originalHeaders, groupID: *key.GroupID, apiKeyID: key.ID}, true
}

func (h *GatewayHandler) prepareClaudePrivacy(c *gin.Context, ingress *claudePrivacyIngress, body []byte, countTokens bool) ([]byte, bool) {
	if ingress == nil {
		return body, true
	}
	prepared, err := ingress.engine.Prepare(service.ClaudePrivacyInput{
		GroupID: ingress.groupID, APIKeyID: ingress.apiKeyID, Body: body, Headers: ingress.headers, CountTokens: countTokens,
	})
	ingress.headers = nil
	if err != nil {
		c.Request.Body = http.NoBody
		c.Request.GetBody = nil
		h.claudePrivacyError(c, err)
		return nil, false
	}
	body = prepared.IngressBody()
	c.Request.Header = prepared.IngressHeaders()
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Body = pkghttputil.NewPrereadBody(body)
	c.Request.ContentLength = int64(len(body))
	c.Request.GetBody = nil
	ctx := service.WithPreparedClaudePrivacy(c.Request.Context(), prepared)
	c.Request = c.Request.WithContext(service.SetClaudeCodeClient(ctx, true))
	return body, true
}

func (h *GatewayHandler) claudePrivacyError(c *gin.Context, err error) {
	if _, prepared := service.ClaudePrivacyRoutingKey(c.Request.Context()); !prepared {
		c.Request.Body, c.Request.GetBody = http.NoBody, nil
		c.Request.ContentLength = 0
	}
	status, code := http.StatusServiceUnavailable, "privacy_unavailable"
	var privacyErr *service.ClaudePrivacyError
	if errors.As(err, &privacyErr) {
		status, code = privacyErr.Status, privacyErr.Code
	}
	c.Set("claude_identity_privacy_error", code)
	h.handleStreamingAwareError(c, status, "invalid_request_error", code, c.Writer.Written())
}

// Redact before the asynchronous logger takes ownership of a snapshot. Error
// bodies can echo prompts or headers even when our outgoing identity is safe.
func sanitizeClaudePrivacyOps(c *gin.Context, entry *service.OpsInsertErrorLogInput) {
	if c == nil || c.Request == nil || entry == nil || !service.ClaudeIdentityPrivacyEnabled(c.Request.Context()) {
		return
	}
	entry.ErrorMessage = c.GetString("claude_identity_privacy_error")
	if entry.ErrorMessage == "" {
		entry.ErrorMessage = "privacy_request_error"
	}
	entry.ErrorBody, entry.APIKeyPrefix = "", ""
	entry.UpstreamErrorMessage, entry.UpstreamErrorDetail, entry.UpstreamErrorsJSON = nil, nil, nil
	entry.UserAgent = c.GetHeader("User-Agent")
	entry.RequestID, _ = c.Request.Context().Value(ctxkey.RequestID).(string)
	entry.ClientRequestID = entry.RequestID
	for i, event := range entry.UpstreamErrors {
		if event == nil {
			continue
		}
		copy := *event
		copy.Message, copy.Detail, copy.UpstreamResponseBody, copy.UpstreamRequestID = "privacy_upstream_error", "", "", ""
		entry.UpstreamErrors[i] = &copy
	}
}

func (h *GatewayHandler) claudePrivacyTargetAllowed(c *gin.Context, account *service.Account) bool {
	if err := service.ValidateClaudePrivacyTarget(c.Request.Context(), account); err != nil {
		h.claudePrivacyError(c, err)
		return false
	}
	return true
}

func (h *GatewayHandler) gatewaySessionHash(c *gin.Context, parsed *service.ParsedRequest) string {
	if key, private := service.ClaudePrivacyRoutingKey(c.Request.Context()); private {
		return key
	}
	return h.gatewayService.GenerateSessionHash(parsed)
}
