package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	middleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type claudePrivacyHandlerRepo struct {
	service.SettingRepository
	raw string
	err error
}

func (r *claudePrivacyHandlerRepo) GetMultiple(context.Context, []string) (map[string]string, error) {
	return map[string]string{service.SettingKeyClaudeCodeIdentityPrivacy: r.raw}, r.err
}

func privacyHandlerTest(t *testing.T, raw string) (*GatewayHandler, *gin.Context, *httptest.ResponseRecorder, *service.APIKey) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Gateway: config.GatewayConfig{ClaudeIdentityPrivacy: config.ClaudeIdentityPrivacyConfig{Key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), Namespace: "handler-test"}}}
	h := &GatewayHandler{cfg: cfg, settingService: service.NewSettingService(&claudePrivacyHandlerRepo{raw: raw}, cfg)}
	r := httptest.NewRecorder()
	c, engine := gin.CreateTestContext(r)
	require.NoError(t, engine.SetTrustedProxies([]string{"127.0.0.0/8"}))
	ctx := context.WithValue(context.Background(), ctxkey.RequestID, "local-request-marker")
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil).WithContext(ctx)
	c.Request.RemoteAddr = "127.0.0.1:12345"
	c.Request.Header.Set("X-Forwarded-For", "198.51.100.17")
	c.Request.Header.Set("User-Agent", "claude-cli/2.1.300 (external, sdk-cli) local-ua-marker")
	c.Request.Header.Set("X-Stainless-Os", "local-os-marker")
	c.Request.Header.Set("Authorization", "Bearer local-key-marker")
	c.Request.Header.Set("X-Request-ID", "local-request-marker")
	c.Request.Header.Set("X-Claude-Code-Session-Id", "44e4c5bc-91b2-4f08-a51a-d92140f886bd")
	g := int64(7)
	key := &service.APIKey{ID: 19, UserID: 31, Key: "local-key-marker", GroupID: &g, Group: &service.Group{ID: g, Platform: service.PlatformAnthropic}}
	c.Set(string(middleware.ContextKeyAPIKey), key)
	c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 31})
	return h, c, r, key
}

func TestClaudePrivacyIngressStopsBeforeServices(t *testing.T) {
	for _, endpoint := range []string{"messages", "count_tokens"} {
		for _, name := range []string{"safeguards", "malformed", "missing_key", "unsupported_group", "unavailable_settings"} {
			t.Run(endpoint+"/"+name, func(t *testing.T) {
				h, c, r, key := privacyHandlerTest(t, `{"version":1,"enabled_group_ids":[7]}`)
				body := `{"model":"claude-sonnet-4-6","messages":[],"safeguards":[{"classifier_context":{"user_identity":"local-body-marker"}}]}`
				want := 400
				switch name {
				case "malformed":
					body = `{"metadata":"local-body-marker",`
				case "missing_key":
					h.cfg.Gateway.ClaudeIdentityPrivacy.Key = ""
					want = 503
				case "unsupported_group":
					key.Group.Platform = service.PlatformOpenAI
					want = 503
				case "unavailable_settings":
					h.settingService = service.NewSettingService(&claudePrivacyHandlerRepo{err: errors.New("local-db-marker")}, h.cfg)
					want = 503
				}
				c.Request.Body = io.NopCloser(strings.NewReader(body))
				c.Request.ContentLength = int64(len(body))
				if endpoint == "messages" {
					h.Messages(c)
				} else {
					c.Request.URL.Path = "/v1/messages/count_tokens"
					h.CountTokens(c)
				}
				require.Equal(t, want, r.Code, r.Body.String())
				require.NotContains(t, r.Body.String(), "local-")
				require.True(t, service.ClaudeIdentityPrivacyEnabled(c.Request.Context()))
				require.NotEqual(t, "local-request-marker", r.Header().Get("X-Request-ID"))
				require.Empty(t, c.GetHeader("User-Agent"))
				require.Empty(t, c.GetHeader("Authorization"))
				_, selected := c.Get(opsAccountIDKey)
				require.False(t, selected)
			})
		}
	}
}

func TestClaudePrivacyIngressSanitizesAndKeepsIPPolicy(t *testing.T) {
	h, c, _, key := privacyHandlerTest(t, `{"version":1,"enabled_group_ids":[7]}`)
	ip.SetForwardedIPSettings(c, false, nil)
	before, trusted := ip.GetClientIP(c), ip.GetTrustedClientIP(c)
	stage, ok := h.beginClaudePrivacy(c, key)
	require.True(t, ok)
	require.Equal(t, before, ip.GetClientIP(c))
	require.Equal(t, trusted, ip.GetTrustedClientIP(c))
	require.Empty(t, c.GetHeader("X-Forwarded-For"))
	body := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"test"}],"metadata":{"user_id":"{\"device_id\":\"local-device-marker\",\"account_uuid\":\"local-account-marker\",\"session_id\":\"44e4c5bc-91b2-4f08-a51a-d92140f886bd\"}"}}`)
	safe, ok := h.prepareClaudePrivacy(c, stage, body, false)
	require.True(t, ok)
	require.Nil(t, stage.headers)
	require.NotContains(t, string(safe), "local-")
	require.NotContains(t, string(safe), "44e4c5bc-91b2-4f08-a51a-d92140f886bd")
	require.Equal(t, "claude-cli/2.1.300 (external, sdk-cli)", c.GetHeader("User-Agent"))
	parsed, err := service.ParseGatewayRequest(service.NewRequestBodyRef(safe), service.PlatformAnthropic)
	require.NoError(t, err)
	SetClaudeCodeClientContext(c, safe, parsed)
	require.True(t, service.IsClaudeCodeClient(c.Request.Context()))
	session, ok := service.ClaudePrivacyRoutingKey(c.Request.Context())
	require.True(t, ok)
	require.Equal(t, session, h.gatewaySessionHash(c, parsed))
	require.Equal(t, before, ip.GetClientIP(c))
	require.Equal(t, trusted, ip.GetTrustedClientIP(c))
	_, ok = h.prepareClaudePrivacy(c, nil, safe, false)
	require.True(t, ok)
}

func TestClaudePrivacyDisabledDoesNotChangeIngress(t *testing.T) {
	h, c, _, key := privacyHandlerTest(t, "")
	original := c.Request.Header.Clone()
	stage, ok := h.beginClaudePrivacy(c, key)
	require.True(t, ok)
	require.Nil(t, stage)
	require.Equal(t, original, c.Request.Header)
	require.False(t, service.ClaudeIdentityPrivacyEnabled(c.Request.Context()))
}

func TestClaudePrivacyMiddlewareDecodesAndPreparesOnlyOnce(t *testing.T) {
	for _, encoding := range []string{"identity", "gzip", "unsupported-local-marker"} {
		t.Run(encoding, func(t *testing.T) {
			h, original, _, key := privacyHandlerTest(t, `{"version":1,"enabled_group_ids":[7]}`)
			body := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"test"}]}`)
			var encoded bytes.Buffer
			if encoding == "gzip" {
				writer := gzip.NewWriter(&encoded)
				_, err := writer.Write(body)
				require.NoError(t, err)
				require.NoError(t, writer.Close())
			} else {
				_, err := encoded.Write(body)
				require.NoError(t, err)
			}
			called := false
			router := gin.New()
			router.POST("/v1/messages", func(c *gin.Context) { c.Set(string(middleware.ContextKeyAPIKey), key); c.Next() }, h.ClaudeIdentityPrivacyMiddleware(), func(c *gin.Context) {
				called = true
				require.True(t, service.ClaudeIdentityPrivacyEnabled(c.Request.Context()))
				require.Empty(t, c.GetHeader("Content-Encoding"))
				sid := c.GetHeader("X-Claude-Code-Session-Id")
				require.NotEqual(t, original.GetHeader("X-Claude-Code-Session-Id"), sid)
				stage, ok := h.beginClaudePrivacy(c, key)
				require.True(t, ok)
				require.Nil(t, stage)
				decoded, err := readLenientJSONRequestBodyWithPrealloc(c.Request, h.cfg)
				require.NoError(t, err)
				safe, ok := h.prepareClaudePrivacy(c, stage, decoded, false)
				require.True(t, ok)
				require.JSONEq(t, string(body), string(safe))
				require.Equal(t, sid, c.GetHeader("X-Claude-Code-Session-Id"))
				c.Status(http.StatusNoContent)
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(encoded.Bytes()))
			req.Header = original.Request.Header.Clone()
			req.Header.Set("Content-Encoding", encoding)
			r := httptest.NewRecorder()
			router.ServeHTTP(r, req)
			if encoding == "unsupported-local-marker" {
				require.False(t, called)
				require.Equal(t, 400, r.Code)
				require.NotContains(t, r.Body.String(), "local-marker")
			} else {
				require.True(t, called)
				require.Equal(t, 204, r.Code)
			}
		})
	}
}

func TestClaudePrivacyErrorQueueSnapshot(t *testing.T) {
	h, c, _, key := privacyHandlerTest(t, `{"version":1,"enabled_group_ids":[7]}`)
	_, ok := h.beginClaudePrivacy(c, key)
	require.True(t, ok)
	marker := "local-private-marker"
	event := &service.OpsUpstreamErrorEvent{AccountID: 71, UpstreamStatusCode: 429, Message: marker, Detail: marker, UpstreamRequestID: marker, UpstreamResponseBody: marker}
	entry := &service.OpsInsertErrorLogInput{RequestID: marker, ClientRequestID: marker, UserAgent: marker, APIKeyPrefix: marker, ErrorMessage: marker, ErrorBody: marker, UpstreamErrorMessage: &marker, UpstreamErrorDetail: &marker, UpstreamErrors: []*service.OpsUpstreamErrorEvent{event}, UpstreamErrorsJSON: &marker}
	sanitizeClaudePrivacyOps(c, entry)
	b, err := json.Marshal(entry)
	require.NoError(t, err)
	require.NotContains(t, string(b), marker)
	require.Equal(t, 71, int(entry.UpstreamErrors[0].AccountID))
	require.Equal(t, 429, entry.UpstreamErrors[0].UpstreamStatusCode)
	require.Equal(t, marker, event.Message, "do not mutate shared attempt snapshots")
}
