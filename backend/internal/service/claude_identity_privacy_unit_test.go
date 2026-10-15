//go:build unit

package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type privacyLogSink struct {
	mu     sync.Mutex
	events []string
}

func (s *privacyLogSink) WriteLogEvent(event *logger.LogEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(event)
	s.events = append(s.events, string(b))
}

func TestClaudePrivacyErrorDiagnosticsDoNotPersistEchoes(t *testing.T) {
	logger.InitBootstrap()
	sink := &privacyLogSink{}
	logger.SetSink(sink)
	t.Cleanup(func() { logger.SetSink(nil) })
	marker := "local-private-error-marker"
	file, err := os.Create(filepath.Join(t.TempDir(), "gateway-debug.log"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })
	for _, count := range []bool{false, true} {
		for _, status := range []int{400, 401, 403, 429, 500, 503} {
			in := privacyTestInput(t)
			in.CountTokens = count
			p := preparePrivacyTest(t, in)
			ctx := WithPreparedClaudePrivacy(context.Background(), p)
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil).WithContext(ctx)
			c.Request.Header = p.IngressHeaders()
			body := `{"type":"error","error":{"type":"invalid_request_error","message":"` + marker + `"}}`
			upstream := &anthropicHTTPUpstreamRecorder{resp: &http.Response{StatusCode: status, Header: http.Header{"X-Request-Id": {marker}}, Body: io.NopCloser(strings.NewReader(body))}}
			svc := newForwardPartialUsageServiceForTest(upstream)
			svc.cfg.Gateway.LogUpstreamErrorBody = true
			svc.cfg.Gateway.LogUpstreamErrorBodyMaxBytes = 8192
			svc.debugGatewayBodyFile.Store(file)
			repo := &rateLimitAccountRepoStub{}
			svc.rateLimitService = &RateLimitService{accountRepo: repo, cfg: svc.cfg}
			parsed, err := ParseGatewayRequest(NewRequestBodyRef(p.IngressBody()), PlatformAnthropic)
			require.NoError(t, err)
			if count {
				err = svc.ForwardCountTokens(ctx, c, privacyTestAccount(), parsed)
			} else {
				_, err = svc.Forward(ctx, c, privacyTestAccount(), parsed)
			}
			require.Error(t, err)
			require.NotContains(t, err.Error(), marker)
			for _, key := range []string{OpsUpstreamErrorMessageKey, OpsUpstreamErrorDetailKey, OpsUpstreamErrorsKey} {
				value, _ := c.Get(key)
				b, e := json.Marshal(value)
				require.NoError(t, e)
				require.NotContains(t, string(b), marker)
			}
			require.NotContains(t, repo.lastErrorMsg, marker)
			require.NotContains(t, repo.lastTempReason, marker)
		}
	}
	// Direct rate-limit handling must classify the original error and persist
	// only its fixed diagnostic, including the standalone 403 raw-body log.
	ctx := MarkClaudeIdentityPrivacy(context.Background())
	repo := &rateLimitAccountRepoStub{}
	rate := &RateLimitService{accountRepo: repo}
	rate.HandleUpstreamError(ctx, privacyTestAccount(), 403, http.Header{"X-Request-Id": {marker}}, []byte(`{"error":{"message":"`+marker+`"}}`))
	require.Positive(t, repo.setErrorCalls)
	require.NotContains(t, repo.lastErrorMsg, marker)
	sink.mu.Lock()
	events := strings.Join(sink.events, "\n")
	sink.mu.Unlock()
	require.NotEmpty(t, events)
	require.NotContains(t, events, marker)
	stat, err := file.Stat()
	require.NoError(t, err)
	require.Zero(t, stat.Size(), "privacy requests must not create debug body snapshots")
}

func TestClaudePrivacyConflictingBetaPolicyStopsBothBuilders(t *testing.T) {
	resetGatewayForwardingSettingsCacheForTest(t)
	repo := &gatewayTTLSettingRepo{data: map[string]string{SettingKeyBetaPolicySettings: `{"rules":[{"beta_token":"future-capability-2099-01-01","action":"filter","scope":"all"}]}`}}
	svc := &GatewayService{settingService: NewSettingService(repo, nil)}
	for _, count := range []bool{false, true} {
		in := privacyTestInput(t)
		in.CountTokens = count
		p := preparePrivacyTest(t, in)
		_, _, err := svc.buildClaudePrivateRequest(WithPreparedClaudePrivacy(context.Background(), p), privacyTestAccount(), p.IngressBody(), "dummy", "oauth", "claude-sonnet-4-6", count)
		require.EqualError(t, err, "privacy_incompatible_beta_policy")
	}
}
