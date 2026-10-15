package handler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/audit"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/changelog"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/handler"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/sse"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/store"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/tokens"
)

// auditFixture is a handler wired with a real audit log, plus the id of the
// bootstrap device whose token is testToken.
type auditFixture struct {
	h        *handler.Handler
	log      *audit.Log
	tokens   *tokens.Store
	deviceID string
}

func newAuditFixture(t *testing.T, trustProxy bool) *auditFixture {
	dir := t.TempDir()
	ts := newTokens(t, dir)
	l := audit.New(filepath.Join(dir, "audit.jsonl"))
	h := handler.New(store.New(filepath.Join(dir, "vault")), changelog.New(filepath.Join(dir, "changelog.jsonl")), sse.NewBroker(), ts).
		WithAudit(l, trustProxy)
	return &auditFixture{h: h, log: l, tokens: ts, deviceID: ts.List()[0].ID}
}

func (f *auditFixture) do(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	return w
}

func authed(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	return req
}

func (f *auditFixture) events(t *testing.T, event string) []audit.Entry {
	got, err := f.log.Query(audit.Filter{Event: event})
	require.NoError(t, err)
	return got
}

func TestAuditRecordsAuthFailedWithIP(t *testing.T) {
	f := newAuditFixture(t, false)
	req := httptest.NewRequest("GET", "/changes", nil)
	req.RemoteAddr = "9.9.9.9:4321"
	req.Header.Set("Authorization", "Bearer wrong")
	require.Equal(t, http.StatusUnauthorized, f.do(req).Code)

	got := f.events(t, audit.AuthFailed)
	require.Len(t, got, 1)
	require.Equal(t, "9.9.9.9", got[0].IP)
	require.Equal(t, 401, got[0].Status)
	require.Empty(t, got[0].DeviceID)
	require.Equal(t, "/changes", got[0].Path)
}

func TestAuditIPFromForwardedForOnlyWhenTrusted(t *testing.T) {
	for _, trust := range []bool{true, false} {
		f := newAuditFixture(t, trust)
		req := httptest.NewRequest("GET", "/changes", nil)
		req.RemoteAddr = "10.0.0.1:1"
		req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
		f.do(req)

		got := f.events(t, audit.AuthFailed)
		require.Len(t, got, 1)
		if trust {
			require.Equal(t, "1.2.3.4", got[0].IP)
		} else {
			require.Equal(t, "10.0.0.1", got[0].IP)
		}
	}
}

func TestAuditRecordsFilePutAndDelete(t *testing.T) {
	f := newAuditFixture(t, false)
	require.Equal(t, http.StatusOK, f.do(authed("PUT", "/file/notes/a.md", "hello")).Code)

	put := f.events(t, audit.FilePut)
	require.Len(t, put, 1)
	require.Equal(t, f.deviceID, put[0].DeviceID)
	require.Equal(t, "notes/a.md", put[0].Path)
	require.Equal(t, 200, put[0].Status)

	del := authed("DELETE", "/file/notes/a.md", "")
	del.Header.Set("X-Base-Hash", sha256Hex("hello"))
	require.Equal(t, http.StatusOK, f.do(del).Code)
	got := f.events(t, audit.FileDelete)
	require.Len(t, got, 1)
	require.Equal(t, f.deviceID, got[0].DeviceID)
}

func TestAuditCountsPollingInsteadOfLoggingIt(t *testing.T) {
	f := newAuditFixture(t, false)
	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusOK, f.do(authed("GET", "/changes", "")).Code)
	}
	all, err := f.log.Query(audit.Filter{})
	require.NoError(t, err)
	require.Empty(t, all, "polling must not write a line per request")

	require.NoError(t, f.log.Flush())
	got := f.events(t, audit.PollSummary)
	require.Len(t, got, 1)
	require.Equal(t, 3, got[0].Count)
	require.Equal(t, f.deviceID, got[0].DeviceID)
	require.Equal(t, "GET /changes", got[0].Detail)
}

func TestAuditRecordsPairAndRevoke(t *testing.T) {
	f := newAuditFixture(t, false)
	w := f.do(authed("POST", "/pair", `{"label":"phone"}`))
	require.Equal(t, http.StatusOK, w.Code)

	issued := f.events(t, audit.TokenIssued)
	require.Len(t, issued, 1)
	newID := issued[0].DeviceID
	require.NotEmpty(t, newID)
	require.NotEqual(t, f.deviceID, newID, "DeviceID is the affected device, not the caller")
	require.Contains(t, issued[0].Detail, "actor="+f.deviceID)

	require.Equal(t, http.StatusOK, f.do(authed("DELETE", "/devices/"+newID, "")).Code)
	revoked := f.events(t, audit.TokenRevoked)
	require.Len(t, revoked, 1)
	require.Equal(t, newID, revoked[0].DeviceID)
	require.Contains(t, revoked[0].Detail, "actor="+f.deviceID)
}

func TestAuditRecordsSSEConnectAndDisconnect(t *testing.T) {
	f := newAuditFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	req := authed("GET", "/events", "").WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		f.h.ServeHTTP(w, req)
		close(done)
	}()
	cancel()
	<-done

	require.Len(t, f.events(t, audit.SSEConnect), 1)
	disc := f.events(t, audit.SSEDisconnect)
	require.Len(t, disc, 1)
	require.Equal(t, f.deviceID, disc[0].DeviceID)
}

func TestAuditWriteFailureDoesNotBreakSync(t *testing.T) {
	dir := t.TempDir()
	// The journal lives in a directory that does not exist, so every write fails.
	l := audit.New(filepath.Join(dir, "missing", "audit.jsonl"))
	h := handler.New(store.New(filepath.Join(dir, "vault")), changelog.New(filepath.Join(dir, "changelog.jsonl")), sse.NewBroker(), newTokens(t, dir)).
		WithAudit(l, false)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed("PUT", "/file/a.md", "x"))
	require.Equal(t, http.StatusOK, w.Code)
}
