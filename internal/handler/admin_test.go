package handler_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/audit"
)

const adminToken = "admin-secret"

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func adminReq(method, target, token string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = "7.7.7.7:1"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func newAdminFixture(t *testing.T) *auditFixture {
	f := newAuditFixture(t, false)
	f.h.WithAdmin(adminToken)
	return f
}

func TestAdminDisabledWithoutToken(t *testing.T) {
	f := newAuditFixture(t, false) // WithAdmin never called
	for _, target := range []string{"/admin", "/admin/api/devices", "/admin/api/events", "/admin/api/stats"} {
		require.Equal(t, http.StatusNotFound, f.do(adminReq("GET", target, adminToken)).Code, target)
	}
	require.Equal(t, http.StatusNotFound, f.do(adminReq("DELETE", "/admin/api/devices/x", adminToken)).Code)
}

func TestAdminPageIsPublicStaticHTML(t *testing.T) {
	f := newAdminFixture(t)
	w := f.do(adminReq("GET", "/admin", ""))
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Header().Get("Content-Type"), "text/html")
	require.NotContains(t, w.Body.String(), f.deviceID, "the page itself carries no data")
}

func TestAdminAPIRequiresAdminToken(t *testing.T) {
	f := newAdminFixture(t)
	require.Equal(t, http.StatusUnauthorized, f.do(adminReq("GET", "/admin/api/devices", "")).Code)
	require.Equal(t, http.StatusUnauthorized, f.do(adminReq("GET", "/admin/api/devices", "nope")).Code)
	require.Equal(t, http.StatusUnauthorized, f.do(adminReq("GET", "/admin/api/devices", testToken)).Code,
		"a device token must not open the admin API")
	require.Equal(t, http.StatusOK, f.do(adminReq("GET", "/admin/api/devices", adminToken)).Code)
}

func TestAdminTokenDoesNotOpenSync(t *testing.T) {
	f := newAdminFixture(t)
	require.Equal(t, http.StatusUnauthorized, f.do(adminReq("GET", "/changes", adminToken)).Code)
}

func TestAdminListDevicesOmitsSecrets(t *testing.T) {
	f := newAdminFixture(t)
	w := f.do(adminReq("GET", "/admin/api/devices", adminToken))
	require.Equal(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), "tokenHash")
	require.NotContains(t, w.Body.String(), testToken)

	var devs []map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &devs))
	require.Len(t, devs, 1)
	require.Equal(t, f.deviceID, devs[0]["id"])
	require.Equal(t, "bootstrap", devs[0]["label"])
}

func TestAdminRevokeDevice(t *testing.T) {
	f := newAdminFixture(t)
	require.Equal(t, http.StatusOK, f.do(adminReq("DELETE", "/admin/api/devices/"+f.deviceID, adminToken)).Code)

	require.Equal(t, http.StatusUnauthorized, f.do(authed("GET", "/changes", "")).Code, "revoked token no longer works")
	got := f.events(t, audit.TokenRevoked)
	require.Len(t, got, 1)
	require.Equal(t, f.deviceID, got[0].DeviceID)
	require.Equal(t, "actor=admin", got[0].Detail)
}

func TestAdminRevokeUnknownIs404(t *testing.T) {
	f := newAdminFixture(t)
	require.Equal(t, http.StatusNotFound, f.do(adminReq("DELETE", "/admin/api/devices/dev_nope", adminToken)).Code)
}

func TestAdminEventsFilter(t *testing.T) {
	f := newAdminFixture(t)
	require.NoError(t, f.log.Record(audit.Entry{DeviceID: "dev_a", Event: audit.FilePut, Path: "a.md"}))
	require.NoError(t, f.log.Record(audit.Entry{DeviceID: "dev_b", Event: audit.FilePut, Path: "b.md"}))
	require.NoError(t, f.log.Record(audit.Entry{DeviceID: "dev_a", Event: audit.FileDelete, Path: "a.md"}))

	w := f.do(adminReq("GET", "/admin/api/events?device=dev_a&event=file_put", adminToken))
	require.Equal(t, http.StatusOK, w.Code)
	var got []audit.Entry
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Len(t, got, 1)
	require.Equal(t, "a.md", got[0].Path)

	w = f.do(adminReq("GET", "/admin/api/events?limit=1", adminToken))
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Len(t, got, 1)

	bad := f.do(adminReq("GET", "/admin/api/events?since=yesterday", adminToken))
	require.Equal(t, http.StatusBadRequest, bad.Code)

	since := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	w = f.do(adminReq("GET", "/admin/api/events?since="+since, adminToken))
	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, "[]", w.Body.String())
}

func TestAdminStatsIncludesUnflushedPolling(t *testing.T) {
	f := newAdminFixture(t)
	require.Equal(t, http.StatusOK, f.do(authed("GET", "/changes", "")).Code)
	require.Equal(t, http.StatusOK, f.do(authed("GET", "/changes", "")).Code)

	w := f.do(adminReq("GET", "/admin/api/stats", adminToken))
	require.Equal(t, http.StatusOK, w.Code)
	var rows []audit.StatRow
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rows))
	require.Len(t, rows, 1)
	require.Equal(t, f.deviceID, rows[0].DeviceID)
	require.Equal(t, 2, rows[0].Count)
}

func TestAdminFailedLoginsAreLoggedAndRateLimited(t *testing.T) {
	f := newAdminFixture(t)
	for i := 0; i < 10; i++ {
		require.Equal(t, http.StatusUnauthorized, f.do(adminReq("GET", "/admin/api/devices", "bad")).Code)
	}
	failed := f.events(t, audit.AdminLoginFailed)
	require.Len(t, failed, 10)
	require.Equal(t, "7.7.7.7", failed[0].IP)

	// The 11th attempt is blocked even with the correct token.
	require.Equal(t, http.StatusTooManyRequests, f.do(adminReq("GET", "/admin/api/devices", adminToken)).Code)
	require.Len(t, f.events(t, audit.AdminLoginFailed), 10, "blocked requests are not logged again")

	// Another IP is unaffected.
	other := adminReq("GET", "/admin/api/devices", adminToken)
	other.RemoteAddr = "8.8.8.8:1"
	require.Equal(t, http.StatusOK, f.do(other).Code)
}

func TestAdminLabelIsReturnedVerbatimAsJSON(t *testing.T) {
	const label = "<img src=x onerror=alert(1)>"
	f := newAdminFixture(t)
	require.Equal(t, http.StatusOK, f.do(authed("POST", "/pair", `{"label":"`+label+`"}`)).Code)

	w := f.do(adminReq("GET", "/admin/api/devices", adminToken))
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
	var devs []struct{ Label string }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &devs))
	labels := []string{}
	for _, d := range devs {
		labels = append(labels, d.Label)
	}
	// The API returns the label as plain data; rendering it as text is the page's job.
	require.Contains(t, labels, label)
}
