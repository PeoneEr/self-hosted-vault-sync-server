package main_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/changelog"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/handler"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/sse"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/store"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/tokens"
)

const integrationToken = "integration-test"

func startServer(t *testing.T) string {
	dir := t.TempDir()
	s := store.New(filepath.Join(dir, "vault"))
	cl := changelog.New(filepath.Join(dir, "changelog.jsonl"))
	broker := sse.NewBroker()

	ts, err := tokens.New(filepath.Join(dir, "tokens.json"))
	require.NoError(t, err)
	_, _, err = ts.Bootstrap(integrationToken)
	require.NoError(t, err)

	h := handler.New(s, cl, broker, ts)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	return fmt.Sprintf("http://%s", ln.Addr())
}

func authedReq(t *testing.T, method, url string, body []byte, headers map[string]string) *http.Response {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+integrationToken)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func TestIntegration_PutGetChanges(t *testing.T) {
	base := startServer(t)

	before := time.Now().Unix()
	resp := authedReq(t, "PUT", base+"/file/notes/hello.md", []byte("hello"), map[string]string{"X-Base-Hash": ""})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "false", resp.Header.Get("X-Conflict"))

	resp = authedReq(t, "GET", base+"/file/notes/hello.md", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, "hello", string(body))

	resp = authedReq(t, "GET", fmt.Sprintf("%s/changes?since=%d", base, before-1), nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var changes []changelog.Entry
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&changes))
	require.Len(t, changes, 1)
	require.Equal(t, "notes/hello.md", changes[0].Path)
}

func TestIntegration_ConflictCopy(t *testing.T) {
	base := startServer(t)

	initialResp := authedReq(t, "PUT", base+"/file/notes/foo.md", []byte("v1"), map[string]string{"X-Base-Hash": ""})
	v1Hash := initialResp.Header.Get("X-Current-Hash")
	require.NotEmpty(t, v1Hash, "server must return X-Current-Hash on successful write")

	resp := authedReq(t, "PUT", base+"/file/notes/foo.md", []byte("conflicting"), map[string]string{"X-Base-Hash": "stale"})
	require.Equal(t, "true", resp.Header.Get("X-Conflict"))

	// Server must return the canonical's current hash so the client can
	// update its state and stop sending the stale X-Base-Hash.
	currentHash := resp.Header.Get("X-Current-Hash")
	require.NotEmpty(t, currentHash, "server must return X-Current-Hash on conflict response")
	require.Equal(t, v1Hash, currentHash, "X-Current-Hash must equal the canonical's pre-conflict hash")

	resp = authedReq(t, "GET", base+"/file/notes/foo.md", nil, nil)
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, "v1", string(body))

	resp = authedReq(t, "GET", base+"/changes?since=0", nil, nil)
	var changes []changelog.Entry
	json.NewDecoder(resp.Body).Decode(&changes)

	var hasConflict bool
	for _, c := range changes {
		if strings.Contains(c.Path, ".conflict.") {
			hasConflict = true
		}
	}
	require.True(t, hasConflict)
}

// TestIntegration_ConflictDoesNotLoop is a regression test for the 2026-06-23
// conflict storm. The client held a stale X-Base-Hash; each push created a new
// .conflict copy whose SSE event triggered another push with the same stale
// hash, producing ~30 conflict copies in 9 minutes.
//
// Root cause: the server never told the client the canonical's current hash on
// a conflict response. The client retained its stale X-Base-Hash forever and
// every debounce-triggered push hit the conflict branch again.
//
// Fix: server returns X-Current-Hash on every conflict response. The client
// (TypeScript plugin) uses it to update state.files[path] immediately, so the
// next push carries the correct base hash and either succeeds cleanly or
// creates at most one additional conflict if the canonical changed again in the
// interim.
func TestIntegration_ConflictDoesNotLoop(t *testing.T) {
	base := startServer(t)

	// Step 1: initial upload — canonical is at "v1"
	resp := authedReq(t, "PUT", base+"/file/Daily notes/today.md", []byte("v1"), map[string]string{"X-Base-Hash": ""})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "false", resp.Header.Get("X-Conflict"))
	v1Hash := resp.Header.Get("X-Current-Hash")
	require.NotEmpty(t, v1Hash, "server must return X-Current-Hash on successful write")

	// Step 2: second client advances canonical to "v2"
	resp = authedReq(t, "PUT", base+"/file/Daily notes/today.md", []byte("v2"), map[string]string{"X-Base-Hash": v1Hash})
	require.Equal(t, "false", resp.Header.Get("X-Conflict"))
	v2Hash := resp.Header.Get("X-Current-Hash")
	require.NotEmpty(t, v2Hash)
	require.NotEqual(t, v1Hash, v2Hash)

	// Step 3: first client (still holding stale v1Hash) pushes "v3"
	// baseHash=v1Hash, server has v2Hash → conflict
	resp = authedReq(t, "PUT", base+"/file/Daily notes/today.md", []byte("v3"), map[string]string{"X-Base-Hash": v1Hash})
	require.Equal(t, "true", resp.Header.Get("X-Conflict"), "hash mismatch must be flagged as conflict")

	// Server must return the canonical's current hash so the client can
	// reconcile and break the push→conflict→push loop.
	serverCurrentHash := resp.Header.Get("X-Current-Hash")
	require.NotEmpty(t, serverCurrentHash, "server must return X-Current-Hash on conflict response")
	require.Equal(t, v2Hash, serverCurrentHash, "X-Current-Hash must equal the canonical's current hash at conflict time")

	// Step 4: canonical must still hold v2 (not overwritten by the conflict PUT)
	getResp := authedReq(t, "GET", base+"/file/Daily notes/today.md", nil, nil)
	body, _ := io.ReadAll(getResp.Body)
	require.Equal(t, "v2", string(body), "canonical must not be overwritten by a conflicting PUT")

	// Step 5: simulate the loop — push again with the same stale hash.
	// Each stale push must create exactly one conflict copy; the total count
	// is bounded and the canonical is never silently replaced.
	resp2 := authedReq(t, "PUT", base+"/file/Daily notes/today.md", []byte("v3-retry"), map[string]string{"X-Base-Hash": v1Hash})
	require.Equal(t, "true", resp2.Header.Get("X-Conflict"))
	require.Equal(t, v2Hash, resp2.Header.Get("X-Current-Hash"))

	// Two stale pushes → exactly two conflict copies in the changelog.
	// More than two would indicate the server itself is feeding a loop.
	changesResp := authedReq(t, "GET", base+"/changes?since=0", nil, nil)
	var changes []changelog.Entry
	require.NoError(t, json.NewDecoder(changesResp.Body).Decode(&changes))
	var conflictCount int
	for _, c := range changes {
		if strings.Contains(c.Path, ".conflict.") {
			conflictCount++
		}
	}
	require.Equal(t, 2, conflictCount, "each stale push creates exactly one conflict copy; more indicates a server-side loop")

	// Step 6: with the correct X-Base-Hash (serverCurrentHash), push succeeds
	// and canonical advances — confirming the client-side fix path works.
	resp3 := authedReq(t, "PUT", base+"/file/Daily notes/today.md", []byte("v3-reconciled"), map[string]string{"X-Base-Hash": serverCurrentHash})
	require.Equal(t, "false", resp3.Header.Get("X-Conflict"), "push with correct base hash must succeed")
	require.NotEmpty(t, resp3.Header.Get("X-Current-Hash"))

	getResp2 := authedReq(t, "GET", base+"/file/Daily notes/today.md", nil, nil)
	body2, _ := io.ReadAll(getResp2.Body)
	require.Equal(t, "v3-reconciled", string(body2))
}

func TestIntegration_DeleteFile(t *testing.T) {
	base := startServer(t)

	// Upload then get hash from changes
	authedReq(t, "PUT", base+"/file/del.md", []byte("bye"), map[string]string{"X-Base-Hash": ""})

	resp := authedReq(t, "GET", base+"/changes?since=0", nil, nil)
	var changes []changelog.Entry
	json.NewDecoder(resp.Body).Decode(&changes)
	require.Len(t, changes, 1)
	hash := changes[0].Hash

	// Delete with correct hash
	resp = authedReq(t, "DELETE", base+"/file/del.md", nil, map[string]string{"X-Base-Hash": hash})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// File gone
	resp = authedReq(t, "GET", base+"/file/del.md", nil, nil)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestIntegration_PairAndRevoke(t *testing.T) {
	base := startServer(t)

	// Pair a second device using the bootstrap token.
	pairResp := authedReq(t, "POST", base+"/pair", []byte(`{"label":"phone"}`), map[string]string{"Content-Type": "application/json"})
	require.Equal(t, http.StatusOK, pairResp.StatusCode)
	var paired struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(pairResp.Body).Decode(&paired))
	require.NotEmpty(t, paired.Token)

	// The new device's token works for a normal sync call.
	req, _ := http.NewRequest("GET", base+"/changes?since=0", nil)
	req.Header.Set("Authorization", "Bearer "+paired.Token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Revoke the bootstrap device using the new device's token.
	listReq, _ := http.NewRequest("GET", base+"/devices", nil)
	listReq.Header.Set("Authorization", "Bearer "+paired.Token)
	listResp, err := http.DefaultClient.Do(listReq)
	require.NoError(t, err)
	var devices []map[string]any
	require.NoError(t, json.NewDecoder(listResp.Body).Decode(&devices))
	var bootstrapID string
	for _, d := range devices {
		if d["label"] == "bootstrap" {
			bootstrapID = d["id"].(string)
		}
	}
	require.NotEmpty(t, bootstrapID)

	delReq, _ := http.NewRequest("DELETE", base+"/devices/"+bootstrapID, nil)
	delReq.Header.Set("Authorization", "Bearer "+paired.Token)
	delResp, err := http.DefaultClient.Do(delReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, delResp.StatusCode)

	// Original integration token (the bootstrap device) is now rejected.
	oldReq, _ := http.NewRequest("GET", base+"/changes?since=0", nil)
	oldReq.Header.Set("Authorization", "Bearer "+integrationToken)
	oldResp, err := http.DefaultClient.Do(oldReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, oldResp.StatusCode)
}
