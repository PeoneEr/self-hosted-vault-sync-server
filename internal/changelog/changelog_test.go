package changelog_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/changelog"
)

func TestAppendAndSince(t *testing.T) {
	cl := changelog.New(filepath.Join(t.TempDir(), "changelog.jsonl"))

	require.NoError(t, cl.Append(changelog.Entry{TS: 100, Path: "a.md", Hash: "h1", Action: "modified"}))
	require.NoError(t, cl.Append(changelog.Entry{TS: 200, Path: "b.md", Hash: "h2", Action: "modified"}))
	require.NoError(t, cl.Append(changelog.Entry{TS: 300, Path: "a.md", Hash: "", Action: "deleted"}))

	entries, err := cl.Since(150)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	require.Equal(t, "b.md", entries[0].Path)
	require.Equal(t, "a.md", entries[1].Path)
}

func TestSinceEmptyFile(t *testing.T) {
	cl := changelog.New(filepath.Join(t.TempDir(), "changelog.jsonl"))
	entries, err := cl.Since(0)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestSinceZeroReturnsAll(t *testing.T) {
	cl := changelog.New(filepath.Join(t.TempDir(), "changelog.jsonl"))
	require.NoError(t, cl.Append(changelog.Entry{TS: 1, Path: "a.md", Hash: "h", Action: "modified"}))

	entries, err := cl.Since(0)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}
