package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/changelog"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/handler"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/sse"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/store"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/tokens"
)

const testToken = "test-token"

// newTokens returns a tokens.Store, bootstrapped with testToken, backed by
// a fresh temp file under dir.
func newTokens(t *testing.T, dir string) *tokens.Store {
	ts, err := tokens.New(filepath.Join(dir, "tokens.json"))
	require.NoError(t, err)
	_, _, err = ts.Bootstrap(testToken)
	require.NoError(t, err)
	return ts
}

func newHandler(t *testing.T) *handler.Handler {
	dir := t.TempDir()
	s := store.New(filepath.Join(dir, "vault"))
	cl := changelog.New(filepath.Join(dir, "changelog.jsonl"))
	broker := sse.NewBroker()
	return handler.New(s, cl, broker, newTokens(t, dir))
}

func TestAuthRejectsNoToken(t *testing.T) {
	h := newHandler(t)
	req := httptest.NewRequest("GET", "/changes", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthRejectsWrongToken(t *testing.T) {
	h := newHandler(t)
	req := httptest.NewRequest("GET", "/changes", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetChangesEmpty(t *testing.T) {
	h := newHandler(t)
	req := httptest.NewRequest("GET", "/changes?since=0", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var result []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Empty(t, result)
}

func TestGetChangesSince(t *testing.T) {
	dir := t.TempDir()
	cl := changelog.New(filepath.Join(dir, "changelog.jsonl"))
	require.NoError(t, cl.Append(changelog.Entry{TS: 100, Path: "a.md", Hash: "h1", Action: "modified"}))
	require.NoError(t, cl.Append(changelog.Entry{TS: 200, Path: "b.md", Hash: "h2", Action: "modified"}))

	s := store.New(filepath.Join(dir, "vault"))
	h := handler.New(s, cl, sse.NewBroker(), newTokens(t, dir))

	req := httptest.NewRequest("GET", "/changes?since=150", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var result []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Len(t, result, 1)
	require.Equal(t, "b.md", result[0]["path"])
}

func TestGetFileMissing(t *testing.T) {
	h := newHandler(t)
	req := httptest.NewRequest("GET", "/file/notes/missing.md", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetFileExists(t *testing.T) {
	dir := t.TempDir()
	s := store.New(filepath.Join(dir, "vault"))
	require.NoError(t, s.WriteFile("notes/foo.md", []byte("hello")))

	h := handler.New(s, changelog.New(filepath.Join(dir, "changelog.jsonl")), sse.NewBroker(), newTokens(t, dir))

	req := httptest.NewRequest("GET", "/file/notes/foo.md", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "hello", w.Body.String())
}

func TestDeleteFileOK(t *testing.T) {
	dir := t.TempDir()
	s := store.New(filepath.Join(dir, "vault"))
	require.NoError(t, s.WriteFile("notes/foo.md", []byte("hello")))
	hash, _ := s.GetHash("notes/foo.md")

	cl := changelog.New(filepath.Join(dir, "changelog.jsonl"))
	h := handler.New(s, cl, sse.NewBroker(), newTokens(t, dir))

	req := httptest.NewRequest("DELETE", "/file/notes/foo.md", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Base-Hash", hash)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	_, exists := s.GetHash("notes/foo.md")
	require.False(t, exists)
}

func TestDeleteFileHashMismatch(t *testing.T) {
	dir := t.TempDir()
	s := store.New(filepath.Join(dir, "vault"))
	require.NoError(t, s.WriteFile("notes/foo.md", []byte("hello")))

	h := handler.New(s, changelog.New(filepath.Join(dir, "changelog.jsonl")), sse.NewBroker(), newTokens(t, dir))

	req := httptest.NewRequest("DELETE", "/file/notes/foo.md", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Base-Hash", "wrong-hash")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusConflict, w.Code)

	_, exists := s.GetHash("notes/foo.md")
	require.True(t, exists) // not deleted
}

func TestPutFileNewFile(t *testing.T) {
	dir := t.TempDir()
	s := store.New(filepath.Join(dir, "vault"))
	h := handler.New(s, changelog.New(filepath.Join(dir, "changelog.jsonl")), sse.NewBroker(), newTokens(t, dir))

	req := httptest.NewRequest("PUT", "/file/notes/new.md", strings.NewReader("content"))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Base-Hash", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "false", w.Result().Header.Get("X-Conflict"))

	data, err := s.ReadFile("notes/new.md")
	require.NoError(t, err)
	require.Equal(t, "content", string(data))
}

func TestPutFileUpdateNoConflict(t *testing.T) {
	dir := t.TempDir()
	s := store.New(filepath.Join(dir, "vault"))
	require.NoError(t, s.WriteFile("notes/foo.md", []byte("v1")))
	hash, _ := s.GetHash("notes/foo.md")

	h := handler.New(s, changelog.New(filepath.Join(dir, "changelog.jsonl")), sse.NewBroker(), newTokens(t, dir))

	req := httptest.NewRequest("PUT", "/file/notes/foo.md", strings.NewReader("v2"))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Base-Hash", hash)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "false", w.Result().Header.Get("X-Conflict"))

	data, _ := s.ReadFile("notes/foo.md")
	require.Equal(t, "v2", string(data))
}

func TestEventsStreamingSupported(t *testing.T) {
	h := newHandler(t)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/events?token="+testToken, nil).WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		h.ServeHTTP(w, req)
		close(done)
	}()
	cancel()
	<-done

	require.NotEqual(t, http.StatusInternalServerError, w.Code)
	require.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
}

func TestEventsSendsInitialFlush(t *testing.T) {
	h := newHandler(t)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/events?token="+testToken, nil).WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		h.ServeHTTP(w, req)
		close(done)
	}()
	cancel()
	<-done

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
	require.Contains(t, w.Body.String(), ":", "an SSE comment is flushed before any event")
}

func TestEventsAuthFallsBackToHeaderWhenQueryTokenMissing(t *testing.T) {
	h := newHandler(t)

	// No ?token= query param at all — must fall back to the Authorization header.
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/events", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		h.ServeHTTP(w, req)
		close(done)
	}()
	cancel()
	<-done

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
}

func TestPutFileIdenticalContentIsNoOp(t *testing.T) {
	dir := t.TempDir()
	s := store.New(filepath.Join(dir, "vault"))
	require.NoError(t, s.WriteFile("notes/foo.md", []byte("same")))

	cl := changelog.New(filepath.Join(dir, "changelog.jsonl"))
	h := handler.New(s, cl, sse.NewBroker(), newTokens(t, dir))

	req := httptest.NewRequest("PUT", "/file/notes/foo.md", strings.NewReader("same"))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Base-Hash", "stale-hash")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "false", w.Result().Header.Get("X-Conflict"))

	paths, _ := s.ListAll()
	for _, p := range paths {
		require.NotContains(t, p, ".conflict.")
	}
	entries, err := cl.Since(0)
	require.NoError(t, err)
	require.Empty(t, entries, "no changelog entry for unchanged content")
}

func TestPutFileConflict(t *testing.T) {
	dir := t.TempDir()
	s := store.New(filepath.Join(dir, "vault"))
	require.NoError(t, s.WriteFile("notes/foo.md", []byte("server-version")))

	h := handler.New(s, changelog.New(filepath.Join(dir, "changelog.jsonl")), sse.NewBroker(), newTokens(t, dir))

	req := httptest.NewRequest("PUT", "/file/notes/foo.md", strings.NewReader("client-version"))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Base-Hash", "stale-hash")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "true", w.Result().Header.Get("X-Conflict"))

	data, _ := s.ReadFile("notes/foo.md")
	require.Equal(t, "server-version", string(data))

	paths, _ := s.ListAll()
	var conflictPath string
	for _, p := range paths {
		if strings.Contains(p, ".conflict.") {
			conflictPath = p
		}
	}
	require.NotEmpty(t, conflictPath)
	conflictData, _ := s.ReadFile(conflictPath)
	require.Equal(t, "client-version", string(conflictData))
}

func TestPairIssuesNewDeviceToken(t *testing.T) {
	h := newHandler(t)

	req := httptest.NewRequest("POST", "/pair", strings.NewReader(`{"label":"phone"}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var result map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.NotEmpty(t, result["id"])
	require.NotEmpty(t, result["token"])

	// The freshly issued token must itself authenticate.
	req2 := httptest.NewRequest("GET", "/changes?since=0", nil)
	req2.Header.Set("Authorization", "Bearer "+result["token"])
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)
}

func TestPairDefaultsLabelWhenBlank(t *testing.T) {
	h := newHandler(t)

	req := httptest.NewRequest("POST", "/pair", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestPairRequiresAuth(t *testing.T) {
	h := newHandler(t)
	req := httptest.NewRequest("POST", "/pair", strings.NewReader(`{"label":"phone"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListDevicesOmitsTokens(t *testing.T) {
	h := newHandler(t)

	req := httptest.NewRequest("GET", "/devices", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	require.NotContains(t, w.Body.String(), "tokenHash")
	require.NotContains(t, w.Body.String(), testToken)

	var devices []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &devices))
	require.Len(t, devices, 1) // the bootstrap device from newHandler
	require.Equal(t, "bootstrap", devices[0]["label"])
}

func TestRevokeDeviceByID(t *testing.T) {
	h := newHandler(t)

	pairReq := httptest.NewRequest("POST", "/pair", strings.NewReader(`{"label":"phone"}`))
	pairReq.Header.Set("Authorization", "Bearer "+testToken)
	pairW := httptest.NewRecorder()
	h.ServeHTTP(pairW, pairReq)
	var paired map[string]string
	require.NoError(t, json.Unmarshal(pairW.Body.Bytes(), &paired))

	delReq := httptest.NewRequest("DELETE", "/devices/"+paired["id"], nil)
	delReq.Header.Set("Authorization", "Bearer "+testToken)
	delW := httptest.NewRecorder()
	h.ServeHTTP(delW, delReq)
	require.Equal(t, http.StatusOK, delW.Code)

	// Revoked token no longer authenticates.
	req := httptest.NewRequest("GET", "/changes?since=0", nil)
	req.Header.Set("Authorization", "Bearer "+paired["token"])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRevokeUnknownDeviceReturns404(t *testing.T) {
	h := newHandler(t)
	req := httptest.NewRequest("DELETE", "/devices/dev_doesnotexist", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestAnyDeviceCanRevokeAnyOtherDevice(t *testing.T) {
	h := newHandler(t)

	// Pair a second device.
	pairReq := httptest.NewRequest("POST", "/pair", strings.NewReader(`{"label":"phone"}`))
	pairReq.Header.Set("Authorization", "Bearer "+testToken)
	pairW := httptest.NewRecorder()
	h.ServeHTTP(pairW, pairReq)
	var paired map[string]string
	require.NoError(t, json.Unmarshal(pairW.Body.Bytes(), &paired))

	// The NEW device (not the bootstrap device) revokes the bootstrap device.
	devices := httptest.NewRequest("GET", "/devices", nil)
	devices.Header.Set("Authorization", "Bearer "+paired["token"])
	dw := httptest.NewRecorder()
	h.ServeHTTP(dw, devices)
	var list []map[string]any
	require.NoError(t, json.Unmarshal(dw.Body.Bytes(), &list))
	var bootstrapID string
	for _, d := range list {
		if d["label"] == "bootstrap" {
			bootstrapID = d["id"].(string)
		}
	}
	require.NotEmpty(t, bootstrapID)

	delReq := httptest.NewRequest("DELETE", "/devices/"+bootstrapID, nil)
	delReq.Header.Set("Authorization", "Bearer "+paired["token"])
	delW := httptest.NewRecorder()
	h.ServeHTTP(delW, delReq)
	require.Equal(t, http.StatusOK, delW.Code)

	// Original bootstrap token (testToken) no longer works.
	req := httptest.NewRequest("GET", "/changes?since=0", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}
