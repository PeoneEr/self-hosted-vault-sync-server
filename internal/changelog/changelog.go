package changelog

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
)

// Entry represents a single changelog record describing a file change.
type Entry struct {
	TS     int64  `json:"ts"`
	Path   string `json:"path"`
	Hash   string `json:"hash"`
	Action string `json:"action"` // "modified" | "deleted"
}

// Changelog is an append-only JSONL file of Entry records.
// It is safe for concurrent use.
type Changelog struct {
	mu   sync.Mutex
	path string
}

// New returns a Changelog backed by the file at path.
// The file is created on first Append if it does not exist.
func New(path string) *Changelog {
	return &Changelog{path: path}
}

// Append serialises e as a JSON line and appends it to the changelog file.
func (c *Changelog) Append(e Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	f, err := os.OpenFile(c.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(e)
}

// Since returns all entries whose TS is strictly greater than ts.
// If the changelog file does not exist it returns an empty slice without error.
func (c *Changelog) Since(ts int64) ([]Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	f, err := os.Open(c.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var result []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		if e.TS > ts {
			result = append(result, e)
		}
	}
	return result, scanner.Err()
}
