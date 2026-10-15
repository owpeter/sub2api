package repository

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// Capture the bytes after the real HTTPUpstream transport, not just the request
// builder. No real provider or credentials are used.
func TestClaudePrivacyHTTPTransportDoesNotRestoreLocalHeaders(t *testing.T) {
	type capture struct {
		path   string
		header http.Header
		body   []byte
	}
	received := make(chan capture, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received <- capture{r.URL.Path, r.Header.Clone(), b}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"input_tokens":1}`)
	}))
	t.Cleanup(server.Close)
	engine, err := service.NewClaudeIdentityPrivacy(config.ClaudeIdentityPrivacyConfig{Key: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)), Namespace: "transport-test"})
	require.NoError(t, err)
	uid := `{"device_id":"local-device-marker","account_uuid":"local-account-marker","session_id":"319832d5-fb9f-4fa2-948d-81f9738eb17d"}`
	body, err := json.Marshal(map[string]any{"model": "claude-sonnet-4-6", "messages": []any{map[string]any{"role": "user", "content": "test"}}, "metadata": map[string]string{"user_id": uid}})
	require.NoError(t, err)
	upstream := NewHTTPUpstream(nil)
	account := &service.Account{ID: 17, Platform: service.PlatformAnthropic, Type: service.AccountTypeOAuth, Extra: map[string]any{"account_uuid": "ec681610-d04f-4c6b-8b55-ab6f854f7d05"}}
	var session string
	for _, path := range []string{"/v1/messages", "/v1/messages/count_tokens"} {
		p, err := engine.Prepare(service.ClaudePrivacyInput{GroupID: 7, APIKeyID: 19, CountTokens: strings.HasSuffix(path, "count_tokens"), Body: body, Headers: http.Header{
			"User-Agent":               {"claude-cli/2.1.300 (external, sdk-cli) local-UA-marker"},
			"X-Claude-Code-Session-Id": {"319832d5-fb9f-4fa2-948d-81f9738eb17d"},
			"X-Stainless-Os":           {"local-OS-marker"}, "Cookie": {"local-cookie-marker"}, "Forwarded": {"for=local-IP-marker"},
		}})
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(service.WithPreparedClaudePrivacy(context.Background(), p), http.MethodPost, server.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer dummy-upstream-token")
		_, err = p.Apply(account, req, p.IngressBody())
		require.NoError(t, err)
		resp, err := upstream.DoWithTLS(req, "", account.ID, 1, nil)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		got := <-received
		headerJSON, err := json.Marshal(got.header)
		require.NoError(t, err)
		require.NotContains(t, string(headerJSON), "local-")
		require.NotContains(t, string(got.body), "local-")
		require.Equal(t, path, got.path)
		require.Equal(t, "claude-cli/2.1.300 (external, sdk-cli)", got.header.Get("User-Agent"))
		require.Empty(t, got.header.Get("X-Stainless-Helper-Method"))
		require.Empty(t, got.header.Get("X-Client-Request-Id"))
		id := service.ParseMetadataUserID(gjson.GetBytes(got.body, "metadata.user_id").String())
		require.NotNil(t, id)
		require.Equal(t, id.SessionID, got.header.Get("X-Claude-Code-Session-Id"))
		if session == "" {
			session = id.SessionID
		} else {
			require.Equal(t, session, id.SessionID)
		}
	}
}
