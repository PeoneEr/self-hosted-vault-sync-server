// Package tokens manages per-device authentication tokens for the sync
// server. Any device holding a valid token may issue tokens for new
// devices and revoke any device (including itself) — there is no separate
// admin-only credential. This is a deliberate simplification for a
// single-person, self-hosted deployment: every paired device belongs to
// the same person, so peer trust is the right model.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// lastSeenThrottle bounds how often Verify persists a LastSeenAt update,
// so a device polling every few seconds doesn't rewrite tokens.json on
// every request.
const lastSeenThrottle = 5 * time.Minute

// Entry is the on-disk record for one device token. TokenHash is the only
// representation of the secret that ever touches disk.
type Entry struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	TokenHash  string    `json:"tokenHash"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
}

// Device is the public view of an Entry returned over the API — no hash.
type Device struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
}

// Store is a JSON-file-backed list of device tokens, safe for concurrent use.
type Store struct {
	path    string
	mu      sync.Mutex
	entries []Entry
}

// New loads the token store from path, or starts empty if the file doesn't
// exist yet (first run).
func New(path string) (*Store, error) {
	s := &Store{path: path, entries: []Entry{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &s.entries); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) save() error {
	data, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

// Bootstrap ensures at least one device token exists. If the store is
// already non-empty it is a no-op (returns created=false). Otherwise it
// creates one entry labeled "bootstrap" using seed as the raw token (or a
// random one if seed is empty) and returns the raw token so the caller can
// surface it once (e.g. log it) — it is never retrievable again.
func (s *Store) Bootstrap(seed string) (rawToken string, created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) > 0 {
		return "", false, nil
	}
	raw := seed
	if raw == "" {
		raw = randomHex(32)
	}
	now := time.Now().UTC()
	s.entries = append(s.entries, Entry{
		ID:         "dev_" + randomHex(6),
		Label:      "bootstrap",
		TokenHash:  hashToken(raw),
		CreatedAt:  now,
		LastSeenAt: now,
	})
	if err := s.save(); err != nil {
		return "", false, err
	}
	return raw, true, nil
}

// Issue creates a new token for label, persists it, and returns the new
// device's id and its raw token. The raw token is shown to the caller
// exactly once — only its hash is persisted.
func (s *Store) Issue(label string) (id string, rawToken string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = "dev_" + randomHex(6)
	rawToken = randomHex(32)
	now := time.Now().UTC()
	s.entries = append(s.entries, Entry{
		ID:         id,
		Label:      label,
		TokenHash:  hashToken(rawToken),
		CreatedAt:  now,
		LastSeenAt: now,
	})
	if err = s.save(); err != nil {
		return "", "", err
	}
	return id, rawToken, nil
}

// Verify checks rawToken against every stored hash using a constant-time
// comparison. On match it throttles a LastSeenAt update to at most once
// per lastSeenThrottle, and returns the matching entry's id.
func (s *Store) Verify(rawToken string) (id string, ok bool) {
	if rawToken == "" {
		return "", false
	}
	h := hashToken(rawToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.entries {
		if subtle.ConstantTimeCompare([]byte(s.entries[i].TokenHash), []byte(h)) == 1 {
			if time.Since(s.entries[i].LastSeenAt) > lastSeenThrottle {
				s.entries[i].LastSeenAt = time.Now().UTC()
				_ = s.save()
			}
			return s.entries[i].ID, true
		}
	}
	return "", false
}

// List returns every paired device, without exposing token hashes.
func (s *Store) List() []Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Device, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, Device{ID: e.ID, Label: e.Label, CreatedAt: e.CreatedAt, LastSeenAt: e.LastSeenAt})
	}
	return out
}

// Revoke removes the device with the given id. Returns found=false if no
// such id existed (not an error).
func (s *Store) Revoke(id string) (found bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.entries {
		if e.ID == id {
			s.entries = append(s.entries[:i], s.entries[i+1:]...)
			return true, s.save()
		}
	}
	return false, nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
