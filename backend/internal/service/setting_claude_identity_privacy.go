package service

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

const SettingKeyClaudeCodeIdentityPrivacy = "claude_code_identity_privacy"

type ClaudeCodeIdentityPrivacySettings struct {
	Version         int     `json:"version"`
	EnabledGroupIDs []int64 `json:"enabled_group_ids"`
}

func (s ClaudeCodeIdentityPrivacySettings) Enabled(groupID *int64) bool {
	if groupID == nil {
		return false
	}
	for _, id := range s.EnabledGroupIDs {
		if id == *groupID {
			return true
		}
	}
	return false
}

type cachedClaudePrivacySettings struct {
	settings *ClaudeCodeIdentityPrivacySettings
	err      error
	expires  time.Time
}

func parseClaudePrivacySettings(raw string) (*ClaudeCodeIdentityPrivacySettings, error) {
	settings := &ClaudeCodeIdentityPrivacySettings{Version: 1, EnabledGroupIDs: []int64{}}
	if raw == "" {
		return settings, nil
	}
	if err := validatePrivacyJSON([]byte(raw)); err != nil {
		return nil, privacyConfigError("invalid_settings")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(settings); err != nil || settings.Version != 1 || len(settings.EnabledGroupIDs) > 1000 || !strings.HasPrefix(strings.TrimSpace(raw), "{") {
		return nil, privacyConfigError("invalid_settings")
	}
	seen := make(map[int64]bool)
	for _, id := range settings.EnabledGroupIDs {
		if id <= 0 || seen[id] {
			return nil, privacyConfigError("invalid_settings")
		}
		seen[id] = true
	}
	if settings.EnabledGroupIDs == nil {
		settings.EnabledGroupIDs = []int64{}
	}
	sort.Slice(settings.EnabledGroupIDs, func(i, j int) bool { return settings.EnabledGroupIDs[i] < settings.EnabledGroupIDs[j] })
	return settings, nil
}

func cloneClaudePrivacySettings(s *ClaudeCodeIdentityPrivacySettings) *ClaudeCodeIdentityPrivacySettings {
	if s == nil {
		return nil
	}
	return &ClaudeCodeIdentityPrivacySettings{Version: s.Version, EnabledGroupIDs: append([]int64{}, s.EnabledGroupIDs...)}
}

func (s *SettingService) ClaudeIdentityPrivacyReady() bool {
	if s == nil || s.cfg == nil {
		return false
	}
	_, err := NewClaudeIdentityPrivacy(s.cfg.Gateway.ClaudeIdentityPrivacy)
	return err == nil
}

// A bounded, per-service cache. Expiry/lookup errors never downgrade to disabled
// or stale settings; administrative changes invalidate this replica immediately.
func (s *SettingService) GetClaudeIdentityPrivacySettings(ctx context.Context) (*ClaudeCodeIdentityPrivacySettings, error) {
	if s == nil || s.settingRepo == nil {
		return nil, privacyConfigError("settings_unavailable")
	}
	if cached := s.claudePrivacyCache.Load(); cached != nil && time.Now().Before(cached.expires) {
		return cloneClaudePrivacySettings(cached.settings), cached.err
	}
	s.claudePrivacyMu.Lock()
	defer s.claudePrivacyMu.Unlock()
	if cached := s.claudePrivacyCache.Load(); cached != nil && time.Now().Before(cached.expires) {
		return cloneClaudePrivacySettings(cached.settings), cached.err
	}
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	values, err := s.settingRepo.GetMultiple(dbCtx, []string{SettingKeyClaudeCodeIdentityPrivacy})
	var settings *ClaudeCodeIdentityPrivacySettings
	if err != nil {
		err = privacyConfigError("settings_unavailable")
	} else {
		settings, err = parseClaudePrivacySettings(values[SettingKeyClaudeCodeIdentityPrivacy])
	}
	ttl := 5 * time.Second
	if err != nil {
		ttl = time.Second
	}
	s.claudePrivacyCache.Store(&cachedClaudePrivacySettings{settings: settings, err: err, expires: time.Now().Add(ttl)})
	return cloneClaudePrivacySettings(settings), err
}

func (s *SettingService) claudePrivacySettingUpdate(ctx context.Context, value *ClaudeCodeIdentityPrivacySettings) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", privacyConfigError("invalid_settings")
	}
	normalized, err := parseClaudePrivacySettings(string(raw))
	if err != nil {
		return "", err
	}
	if len(normalized.EnabledGroupIDs) > 0 {
		if !s.ClaudeIdentityPrivacyReady() {
			return "", privacyConfigError("key_not_configured")
		}
		if s.defaultSubGroupReader == nil {
			return "", privacyConfigError("group_validation_unavailable")
		}
		for _, id := range normalized.EnabledGroupIDs {
			group, err := s.defaultSubGroupReader.GetByID(ctx, id)
			if err != nil || group == nil || group.Platform != PlatformAnthropic {
				return "", privacyConfigError("unsupported_group")
			}
		}
	}
	raw, _ = json.Marshal(normalized)
	return string(raw), nil
}
