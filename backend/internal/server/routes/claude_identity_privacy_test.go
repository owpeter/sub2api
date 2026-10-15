package routes

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type privacyRouteSettingsRepo struct{ service.SettingRepository }

func (*privacyRouteSettingsRepo) GetMultiple(context.Context, []string) (map[string]string, error) {
	return map[string]string{service.SettingKeyClaudeCodeIdentityPrivacy: `{"version":1,"enabled_group_ids":[7]}`}, nil
}

func TestClaudePrivacyRoutesGuardBeforePlatformAndModelDispatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, platform := range []string{service.PlatformAnthropic, service.PlatformOpenAI, service.PlatformComposite, service.PlatformGrok} {
		for _, path := range []string{"/v1/messages", "/v1/messages/count_tokens", "/messages/count_tokens", "/antigravity/v1/messages", "/antigravity/v1/messages/count_tokens"} {
			t.Run(platform+path, func(t *testing.T) {
				cfg := &config.Config{Gateway: config.GatewayConfig{MaxBodySize: 1048576, ClaudeIdentityPrivacy: config.ClaudeIdentityPrivacyConfig{Namespace: "route-test", Key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))}}}
				settings := service.NewSettingService(&privacyRouteSettingsRepo{}, cfg)
				gateway := handler.NewGatewayHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, cfg, settings)
				r := gin.New()
				RegisterGatewayRoutes(r, &handler.Handlers{Gateway: gateway, OpenAIGateway: &handler.OpenAIGatewayHandler{}, AsyncImage: handler.NewAsyncImageHandler(nil, nil)}, middleware.APIKeyAuthMiddleware(func(c *gin.Context) {
					g := int64(7)
					c.Set(string(middleware.ContextKeyAPIKey), &service.APIKey{ID: 19, GroupID: &g, Group: &service.Group{ID: g, Platform: platform}})
					c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 31})
					c.Next()
				}), nil, nil, nil, settings, nil, cfg)
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"model":"claude-sonnet-4-6","safeguards":[{"classifier_context":{"user_identity":"local-route-marker"}}]}`))
				req.Header.Set("User-Agent", "claude-cli/2.1.300 (external, sdk-cli) local-header-marker")
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				if platform == service.PlatformAnthropic && !strings.HasPrefix(path, "/antigravity/") {
					require.Equal(t, 400, w.Code)
				} else {
					require.Equal(t, 503, w.Code)
				}
				require.Contains(t, w.Body.String(), "privacy_")
				require.NotContains(t, w.Body.String(), "local-")
			})
		}
	}
}
