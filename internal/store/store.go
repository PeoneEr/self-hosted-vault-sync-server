package store

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Store manages vault files using content-addressable blob storage.
// Files are stored as blobs/{sha256[:2]}/{sha256[2:]} with a path→hash
// index in index.json. This decouples storage from filesystem naming
// constraints (no 255-byte filename limit regardless of vault path length).
type Store struct {
	root string
	mu   sync.RWMutex
	idx  map[string]string // vault path → content sha256hex
}

func New(root string) *Store {
	s := &Store{root: filepath.Clean(root), idx: make(map[string]string)}
	_ = os.MkdirAll(filepath.Join(root, "blobs"), 0755)
	_ = s.loadIndex()
	return s
}

func (s *Store) blobPath(contentHash string) string {
	return filepath.Join(s.root, "blobs", contentHash[:2], contentHash[2:])
}

func (s *Store) indexPath() string {
	return filepath.Join(s.root, "index.json")
}

func (s *Store) loadIndex() error {
	data, err := os.ReadFile(s.indexPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.idx)
}

func (s *Store) saveIndex() error {
	data, err := json.Marshal(s.idx)
	if err != nil {
		return err
	}
	return os.WriteFile(s.indexPath(), data, 0644)
}

func (s *Store) GetHash(path string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.idx[path]
	return h, ok
}

func (s *Store) ReadFile(path string) ([]byte, error) {
	s.mu.RLock()
	h, ok := s.idx[path]
	s.mu.RUnlock()
	if !ok {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(s.blobPath(h))
}

func (s *Store) WriteFile(path string, data []byte) error {
	h := sha256hex(data)
	bp := s.blobPath(h)
	if err := os.MkdirAll(filepath.Dir(bp), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(bp, data, 0644); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idx[path] = h
	return s.saveIndex()
}

func (s *Store) DeleteFile(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.idx[path]; !ok {
		return os.ErrNotExist
	}
	delete(s.idx, path)
	return s.saveIndex()
}

func (s *Store) ListAll() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	paths := make([]string, 0, len(s.idx))
	for p := range s.idx {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, nil
}

func sha256hex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}
