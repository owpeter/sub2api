//go:build unit

package admin

import (
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestClaudePrivacyAdminPartialUpdateAndRepair(t *testing.T) {
	raw := `{"version":1,"enabled_group_ids":[7]}`
	h, repo := newStepUpSwitchTestHandler(t, map[string]string{service.SettingKeyClaudeCodeIdentityPrivacy: raw})
	r := doUpdateSettings(t, h, map[string]any{"site_name": "Privacy test"}, nil)
	require.Equal(t, http.StatusOK, r.Code, r.Body.String())
	require.Equal(t, raw, repo.values[service.SettingKeyClaudeCodeIdentityPrivacy])
	repo.values[service.SettingKeyClaudeCodeIdentityPrivacy] = `{"version":99}`
	r = doUpdateSettings(t, h, map[string]any{"claude_code_identity_privacy": map[string]any{"version": 1, "enabled_group_ids": []int64{}}}, nil)
	require.Equal(t, http.StatusOK, r.Code, r.Body.String())
	require.JSONEq(t, `{"version":1,"enabled_group_ids":[]}`, repo.values[service.SettingKeyClaudeCodeIdentityPrivacy])
	require.Contains(t, r.Body.String(), `"claude_code_identity_privacy_ready":false`)
}

func TestClaudePrivacyAdminCannotEnableWithoutDeploymentKey(t *testing.T) {
	h, repo := newStepUpSwitchTestHandler(t, map[string]string{})
	r := doUpdateSettings(t, h, map[string]any{"claude_code_identity_privacy": map[string]any{"version": 1, "enabled_group_ids": []int64{7}}}, nil)
	require.Equal(t, http.StatusBadRequest, r.Code, r.Body.String())
	require.Contains(t, r.Body.String(), "privacy_key_not_configured")
	_, exists := repo.values[service.SettingKeyClaudeCodeIdentityPrivacy]
	require.False(t, exists)
}
