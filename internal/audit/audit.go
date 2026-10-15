// Package audit keeps an append-only JSONL journal of device-token activity
// for the admin UI: significant events are written one line each, while
// high-frequency requests (polling) are counted in memory and flushed as
// periodic poll_summary deltas so the file doesn't fill with noise.
package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"os"
	"sort"
	"sync"
	"time"
)

// Event names written to the journal.
const (
	FilePut          = "file_put"
	FileDelete       = "file_delete"
	SSEConnect       = "sse_connect"
	SSEDisconnect    = "sse_disconnect"
	TokenIssued      = "token_issued"
	TokenRevoked     = "token_revoked"
	AuthFailed       = "auth_failed"
	AdminLoginFailed = "admin_login_failed"
	PollSummary      = "poll_summary"
)

// DefaultLimit and MaxLimit bound the number of entries Query returns.
const (
	DefaultLimit = 100
	MaxLimit     = 500
)

const (
	flushInterval = 5 * time.Minute
	pruneInterval = 24 * time.Hour
)

// Entry is one journal line. For PollSummary, Detail is the request kind
// (e.g. "GET /changes"), Count is the number of requests and TS is the time
// of the flush.
type Entry struct {
	TS       time.Time `json:"ts"`
	DeviceID string    `json:"deviceId,omitempty"`
	Event    string    `json:"event"`
	Path     string    `json:"path,omitempty"`
	Status   int       `json:"status,omitempty"`
	IP       string    `json:"ip,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Count    int       `json:"count,omitempty"`
}

// Filter narrows a Query. Zero values mean "no constraint".
type Filter struct {
	DeviceID string
	Event    string
	Exclude  string // drop entries of this event type (e.g. PollSummary)
	Since    time.Time
	Limit    int
}

// StatRow is the number of polling requests of one kind by one device in
// one hour.
type StatRow struct {
	DeviceID string    `json:"deviceId"`
	Kind     string    `json:"kind"`
	Hour     time.Time `json:"hour"`
	Count    int       `json:"count"`
}

type pollKey struct{ device, kind string }

// Log is a JSONL-file-backed journal, safe for concurrent use.
type Log struct {
	path string

	mu     sync.Mutex // guards the file
	pollMu sync.Mutex // guards polls
	polls  map[pollKey]int
}

// New returns a Log writing to path. The file is created on first write.
func New(path string) *Log {
	return &Log{path: path, polls: map[pollKey]int{}}
}

// Record appends e to the journal, stamping TS with the current time if unset.
func (l *Log) Record(e Entry) error {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendLocked(e)
}

func (l *Log) appendLocked(e Entry) error {
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(e)
}

// Count tallies one high-frequency request of the given kind by deviceID.
// It is cheap and never touches disk; Flush persists the tallies.
func (l *Log) Count(deviceID, kind string) {
	l.pollMu.Lock()
	l.polls[pollKey{deviceID, kind}]++
	l.pollMu.Unlock()
}

// Flush writes the in-memory tallies as poll_summary entries and resets them.
func (l *Log) Flush() error {
	l.pollMu.Lock()
	polls := l.polls
	l.polls = map[pollKey]int{}
	l.pollMu.Unlock()
	if len(polls) == 0 {
		return nil
	}

	now := time.Now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	var firstErr error
	for k, n := range polls {
		e := Entry{TS: now, DeviceID: k.device, Event: PollSummary, Detail: k.kind, Count: n}
		if err := l.appendLocked(e); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// readAll returns every parseable entry in file order. A missing file is
// an empty journal; unparseable lines are skipped.
func (l *Log) readAll() ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// Query returns entries matching f, newest first, capped at f.Limit
// (DefaultLimit if unset, never more than MaxLimit).
func (l *Log) Query(f Filter) ([]Entry, error) {
	all, err := l.readAll()
	if err != nil {
		return nil, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	out := []Entry{}
	// Entries are appended in time order, so walking backwards is newest first.
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		e := all[i]
		if f.DeviceID != "" && e.DeviceID != f.DeviceID {
			continue
		}
		if f.Event != "" && e.Event != f.Event {
			continue
		}
		if f.Exclude != "" && e.Event == f.Exclude {
			continue
		}
		if !f.Since.IsZero() && e.TS.Before(f.Since) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// Stats sums poll_summary entries since the given time per device, kind and
// hour, ordered by hour then device.
func (l *Log) Stats(since time.Time) ([]StatRow, error) {
	all, err := l.readAll()
	if err != nil {
		return nil, err
	}
	type key struct {
		device, kind string
		hour         time.Time
	}
	sums := map[key]int{}
	for _, e := range all {
		if e.Event != PollSummary || (!since.IsZero() && e.TS.Before(since)) {
			continue
		}
		sums[key{e.DeviceID, e.Detail, e.TS.UTC().Truncate(time.Hour)}] += e.Count
	}
	rows := make([]StatRow, 0, len(sums))
	for k, n := range sums {
		rows = append(rows, StatRow{DeviceID: k.device, Kind: k.kind, Hour: k.hour, Count: n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].Hour.Equal(rows[j].Hour) {
			return rows[i].Hour.Before(rows[j].Hour)
		}
		if rows[i].DeviceID != rows[j].DeviceID {
			return rows[i].DeviceID < rows[j].DeviceID
		}
		return rows[i].Kind < rows[j].Kind
	})
	return rows, nil
}

// Prune drops entries older than maxAge by rewriting the file.
func (l *Log) Prune(maxAge time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	cutoff := time.Now().UTC().Add(-maxAge)
	tmp := l.path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		f.Close()
		return err
	}
	enc := json.NewEncoder(out)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.TS.Before(cutoff) {
			continue
		}
		if err := enc.Encode(e); err != nil {
			f.Close()
			out.Close()
			os.Remove(tmp)
			return err
		}
	}
	scanErr := sc.Err()
	f.Close()
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if scanErr != nil {
		os.Remove(tmp)
		return scanErr
	}
	return os.Rename(tmp, l.path)
}

// Run flushes the poll tallies every few minutes and prunes entries older
// than retention at start and then daily, until ctx is cancelled (with a
// final flush). Failures are logged, never fatal.
func (l *Log) Run(ctx context.Context, retention time.Duration) {
	if err := l.Prune(retention); err != nil {
		log.Printf("audit: prune: %v", err)
	}
	flush := time.NewTicker(flushInterval)
	prune := time.NewTicker(pruneInterval)
	defer flush.Stop()
	defer prune.Stop()
	for {
		select {
		case <-flush.C:
			if err := l.Flush(); err != nil {
				log.Printf("audit: flush: %v", err)
			}
		case <-prune.C:
			if err := l.Prune(retention); err != nil {
				log.Printf("audit: prune: %v", err)
			}
		case <-ctx.Done():
			if err := l.Flush(); err != nil {
				log.Printf("audit: flush: %v", err)
			}
			return
		}
	}
}
