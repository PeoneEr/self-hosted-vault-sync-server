package tokens_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/tokens"
)

func newStore(t *testing.T) *tokens.Store {
	s, err := tokens.New(filepath.Join(t.TempDir(), "tokens.json"))
	require.NoError(t, err)
	return s
}

func TestBootstrapCreatesTokenWhenEmpty(t *testing.T) {
	s := newStore(t)
	raw, created, err := s.Bootstrap("")
	require.NoError(t, err)
	require.True(t, created)
	require.NotEmpty(t, raw)

	id, ok := s.Verify(raw)
	require.True(t, ok)
	require.NotEmpty(t, id)
}

func TestBootstrapUsesSeedWhenProvided(t *testing.T) {
	s := newStore(t)
	raw, created, err := s.Bootstrap("my-seed-token")
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, "my-seed-token", raw)

	_, ok := s.Verify("my-seed-token")
	require.True(t, ok)
}

func TestBootstrapIsNoOpWhenTokensExist(t *testing.T) {
	s := newStore(t)
	_, _, err := s.Bootstrap("first")
	require.NoError(t, err)

	raw, created, err := s.Bootstrap("second")
	require.NoError(t, err)
	require.False(t, created)
	require.Empty(t, raw)

	// original token still works, "second" was never persisted
	_, ok := s.Verify("first")
	require.True(t, ok)
	_, ok = s.Verify("second")
	require.False(t, ok)
}

func TestIssueCreatesVerifiableToken(t *testing.T) {
	s := newStore(t)
	id, raw, err := s.Issue("phone")
	require.NoError(t, err)
	require.NotEmpty(t, id)
	require.NotEmpty(t, raw)

	gotID, ok := s.Verify(raw)
	require.True(t, ok)
	require.Equal(t, id, gotID)
}

func TestIssuePersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	s1, err := tokens.New(path)
	require.NoError(t, err)
	_, raw, err := s1.Issue("desktop")
	require.NoError(t, err)

	s2, err := tokens.New(path)
	require.NoError(t, err)
	_, ok := s2.Verify(raw)
	require.True(t, ok)
}

func TestVerifyRejectsUnknownToken(t *testing.T) {
	s := newStore(t)
	_, _, err := s.Bootstrap("known")
	require.NoError(t, err)

	_, ok := s.Verify("unknown")
	require.False(t, ok)
}

func TestVerifyRejectsEmptyToken(t *testing.T) {
	s := newStore(t)
	_, ok := s.Verify("")
	require.False(t, ok)
}

func TestListOmitsTokenHash(t *testing.T) {
	s := newStore(t)
	id, _, err := s.Issue("laptop")
	require.NoError(t, err)

	devices := s.List()
	require.Len(t, devices, 1)
	require.Equal(t, id, devices[0].ID)
	require.Equal(t, "laptop", devices[0].Label)
	require.False(t, devices[0].CreatedAt.IsZero())
}

func TestRevokeRemovesDevice(t *testing.T) {
	s := newStore(t)
	id, raw, err := s.Issue("tablet")
	require.NoError(t, err)

	found, err := s.Revoke(id)
	require.NoError(t, err)
	require.True(t, found)

	_, ok := s.Verify(raw)
	require.False(t, ok)
	require.Empty(t, s.List())
}

func TestRevokeUnknownIDReturnsFalse(t *testing.T) {
	s := newStore(t)
	found, err := s.Revoke("dev_doesnotexist")
	require.NoError(t, err)
	require.False(t, found)
}

func TestVerifyUpdatesLastSeenAtThrottled(t *testing.T) {
	s := newStore(t)
	_, raw, err := s.Issue("watch")
	require.NoError(t, err)

	first := s.List()[0].LastSeenAt

	// Immediate re-verify must NOT bump LastSeenAt (throttled to once per 5m).
	_, ok := s.Verify(raw)
	require.True(t, ok)
	second := s.List()[0].LastSeenAt
	require.True(t, second.Equal(first), "LastSeenAt must not change within the throttle window")
}
