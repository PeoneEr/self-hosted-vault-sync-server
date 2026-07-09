package store_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/store"
)

func TestWriteReadHash(t *testing.T) {
	s := store.New(t.TempDir())

	err := s.WriteFile("notes/foo.md", []byte("hello world"))
	require.NoError(t, err)

	data, err := s.ReadFile("notes/foo.md")
	require.NoError(t, err)
	require.Equal(t, []byte("hello world"), data)

	hash, exists := s.GetHash("notes/foo.md")
	require.True(t, exists)
	require.Len(t, hash, 64)
}

func TestGetHashMissing(t *testing.T) {
	s := store.New(t.TempDir())
	_, exists := s.GetHash("missing.md")
	require.False(t, exists)
}

func TestDeleteFile(t *testing.T) {
	s := store.New(t.TempDir())
	require.NoError(t, s.WriteFile("foo.md", []byte("x")))
	require.NoError(t, s.DeleteFile("foo.md"))
	_, exists := s.GetHash("foo.md")
	require.False(t, exists)
}

func TestDeleteMissingFile(t *testing.T) {
	s := store.New(t.TempDir())
	err := s.DeleteFile("missing.md")
	require.Error(t, err)
}

func TestListAll(t *testing.T) {
	s := store.New(t.TempDir())
	require.NoError(t, s.WriteFile("a.md", []byte("a")))
	require.NoError(t, s.WriteFile("sub/b.md", []byte("b")))

	paths, err := s.ListAll()
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"a.md", "sub/b.md"}, paths)
}

func TestLongPathStoredCorrectly(t *testing.T) {
	s := store.New(t.TempDir())
	// Simulate a long Russian filename that would exceed Linux's 255-byte limit
	longPath := "🎙️ Выступления/🎙️ Управление командами и людьми. Как растить инженеров, строить эффективные команды, работать с выгоранием и быть лидером в нестабильном мире.md"

	err := s.WriteFile(longPath, []byte("content"))
	require.NoError(t, err)

	data, err := s.ReadFile(longPath)
	require.NoError(t, err)
	require.Equal(t, []byte("content"), data)
}

func TestIndexPersists(t *testing.T) {
	root := t.TempDir()
	s1 := store.New(root)
	require.NoError(t, s1.WriteFile("note.md", []byte("data")))

	// Re-open store — index should reload
	s2 := store.New(root)
	data, err := s2.ReadFile("note.md")
	require.NoError(t, err)
	require.Equal(t, []byte("data"), data)
}
