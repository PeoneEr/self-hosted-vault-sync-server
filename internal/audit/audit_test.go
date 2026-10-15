package audit_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/audit"
)

func newLog(t *testing.T) (*audit.Log, string) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	return audit.New(path), path
}

func TestQueryMissingFileIsEmpty(t *testing.T) {
	l, _ := newLog(t)
	got, err := l.Query(audit.Filter{})
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestRecordAndQueryNewestFirst(t *testing.T) {
	l, _ := newLog(t)
	base := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, l.Record(audit.Entry{TS: base, DeviceID: "dev_a", Event: audit.FilePut, Path: "a.md", Status: 200}))
	require.NoError(t, l.Record(audit.Entry{TS: base.Add(time.Minute), DeviceID: "dev_a", Event: audit.FileDelete, Path: "a.md", Status: 200}))

	got, err := l.Query(audit.Filter{})
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, audit.FileDelete, got[0].Event)
	require.Equal(t, audit.FilePut, got[1].Event)
}

func TestRecordDefaultsTimestamp(t *testing.T) {
	l, _ := newLog(t)
	require.NoError(t, l.Record(audit.Entry{Event: audit.AuthFailed, IP: "1.2.3.4", Status: 401}))
	got, err := l.Query(audit.Filter{})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.WithinDuration(t, time.Now(), got[0].TS, 5*time.Second)
}

func TestQueryFilters(t *testing.T) {
	l, _ := newLog(t)
	now := time.Now().UTC()
	require.NoError(t, l.Record(audit.Entry{TS: now.Add(-2 * time.Hour), DeviceID: "dev_a", Event: audit.FilePut}))
	require.NoError(t, l.Record(audit.Entry{TS: now.Add(-time.Minute), DeviceID: "dev_a", Event: audit.SSEConnect}))
	require.NoError(t, l.Record(audit.Entry{TS: now.Add(-time.Minute), DeviceID: "dev_b", Event: audit.FilePut}))

	byDevice, err := l.Query(audit.Filter{DeviceID: "dev_a"})
	require.NoError(t, err)
	require.Len(t, byDevice, 2)

	byEvent, err := l.Query(audit.Filter{Event: audit.FilePut})
	require.NoError(t, err)
	require.Len(t, byEvent, 2)

	since, err := l.Query(audit.Filter{Since: now.Add(-time.Hour)})
	require.NoError(t, err)
	require.Len(t, since, 2)
}

func TestQueryLimit(t *testing.T) {
	l, _ := newLog(t)
	for i := 0; i < 5; i++ {
		require.NoError(t, l.Record(audit.Entry{Event: audit.FilePut}))
	}
	got, err := l.Query(audit.Filter{Limit: 2})
	require.NoError(t, err)
	require.Len(t, got, 2)

	got, err = l.Query(audit.Filter{Limit: 100000})
	require.NoError(t, err)
	require.Len(t, got, 5, "limit is capped at MaxLimit, not an error")
}

func TestFlushWritesPollSummary(t *testing.T) {
	l, _ := newLog(t)
	for i := 0; i < 40; i++ {
		l.Count("dev_a", "GET /changes")
	}
	l.Count("dev_a", "GET /file")
	require.NoError(t, l.Flush())

	got, err := l.Query(audit.Filter{Event: audit.PollSummary})
	require.NoError(t, err)
	require.Len(t, got, 2)
	counts := map[string]int{}
	for _, e := range got {
		require.Equal(t, "dev_a", e.DeviceID)
		counts[e.Detail] = e.Count
	}
	require.Equal(t, map[string]int{"GET /changes": 40, "GET /file": 1}, counts)

	// Counters are reset after a flush: a second flush writes nothing new.
	require.NoError(t, l.Flush())
	got, err = l.Query(audit.Filter{Event: audit.PollSummary})
	require.NoError(t, err)
	require.Len(t, got, 2)
}

func TestStatsSumsPollSummaryPerHour(t *testing.T) {
	l, _ := newLog(t)
	h := time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)
	require.NoError(t, l.Record(audit.Entry{TS: h.Add(5 * time.Minute), DeviceID: "dev_a", Event: audit.PollSummary, Detail: "GET /changes", Count: 10}))
	require.NoError(t, l.Record(audit.Entry{TS: h.Add(10 * time.Minute), DeviceID: "dev_a", Event: audit.PollSummary, Detail: "GET /changes", Count: 5}))
	require.NoError(t, l.Record(audit.Entry{TS: h.Add(65 * time.Minute), DeviceID: "dev_a", Event: audit.PollSummary, Detail: "GET /changes", Count: 7}))

	rows, err := l.Stats(time.Time{})
	require.NoError(t, err)
	require.Len(t, rows, 2)
	require.Equal(t, 15, rows[0].Count)
	require.Equal(t, h, rows[0].Hour)
	require.Equal(t, 7, rows[1].Count)
}

func TestPruneDropsOldEntries(t *testing.T) {
	l, _ := newLog(t)
	now := time.Now().UTC()
	require.NoError(t, l.Record(audit.Entry{TS: now.Add(-40 * 24 * time.Hour), Event: audit.FilePut, Path: "old.md"}))
	require.NoError(t, l.Record(audit.Entry{TS: now.Add(-time.Hour), Event: audit.FilePut, Path: "new.md"}))

	require.NoError(t, l.Prune(30*24*time.Hour))

	got, err := l.Query(audit.Filter{})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "new.md", got[0].Path)
}

func TestPruneMissingFileIsNoop(t *testing.T) {
	l, _ := newLog(t)
	require.NoError(t, l.Prune(time.Hour))
}

func TestQueryExcludeEvent(t *testing.T) {
	l, _ := newLog(t)
	require.NoError(t, l.Record(audit.Entry{Event: audit.FilePut}))
	require.NoError(t, l.Record(audit.Entry{Event: audit.PollSummary, Count: 3}))

	got, err := l.Query(audit.Filter{Exclude: audit.PollSummary})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, audit.FilePut, got[0].Event)
}
