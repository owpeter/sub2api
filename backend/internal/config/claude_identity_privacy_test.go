package config

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClaudePrivacyDeploymentEnvironment(t *testing.T) {
	resetViperWithJWTSecret(t)
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	t.Setenv("GATEWAY_CLAUDE_IDENTITY_PRIVACY_KEY", key)
	t.Setenv("GATEWAY_CLAUDE_IDENTITY_PRIVACY_NAMESPACE", "environment-test")
	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, key, cfg.Gateway.ClaudeIdentityPrivacy.Key)
	require.Equal(t, "environment-test", cfg.Gateway.ClaudeIdentityPrivacy.Namespace)
	encoded, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), key)
}
