package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/audit"
)

//go:embed admin.html
var adminPage []byte

const (
	// adminMaxFails failed admin logins within adminFailWindow from one IP
	// block further attempts from that IP with 429.
	adminMaxFails   = 10
	adminFailWindow = time.Minute
	// adminStatsWindow is how far back /admin/api/stats looks by default.
	adminStatsWindow = 24 * time.Hour
)

// adminAuth holds the admin secret (as a hash) and the per-IP failure
// tracking. The zero value is a disabled admin.
type adminAuth struct {
	enabled bool
	hash    [sha256.Size]byte

	mu    sync.Mutex
	fails map[string][]time.Time
}

// WithAdmin enables the admin UI and API, authenticated by token. It is
// separate from device tokens: it opens only /admin/api/*, never sync routes.
// An empty token leaves the admin disabled (all /admin* routes answer 404).
func (h *Handler) WithAdmin(token string) *Handler {
	if token == "" {
		return h
	}
	h.admin.enabled = true
	h.admin.hash = sha256.Sum256([]byte(token))
	h.admin.fails = map[string][]time.Time{}
	return h
}

func (a *adminAuth) verify(token string) bool {
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(sum[:], a.hash[:]) == 1
}

// blocked reports whether ip has used up its failed-attempt budget, and
// forgets attempts older than the window.
func (a *adminAuth) blocked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := time.Now().Add(-adminFailWindow)
	recent := a.fails[ip][:0]
	for _, t := range a.fails[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(a.fails, ip)
		return false
	}
	a.fails[ip] = recent
	return len(recent) >= adminMaxFails
}

func (a *adminAuth) fail(ip string) {
	a.mu.Lock()
	a.fails[ip] = append(a.fails[ip], time.Now())
	a.mu.Unlock()
}

// withAdmin guards a handler with the admin token. Without a configured
// admin it answers 404 so the feature is invisible.
func (h *Handler) withAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.admin.enabled {
			http.NotFound(w, r)
			return
		}
		ip := h.clientIP(r)
		if h.admin.blocked(ip) {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) || !h.admin.verify(strings.TrimPrefix(auth, prefix)) {
			h.admin.fail(ip)
			h.record(audit.Entry{Event: audit.AdminLoginFailed, Path: r.URL.Path, Status: http.StatusUnauthorized, IP: ip})
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// handleAdminPage serves the static admin page. It carries no data and needs
// no auth; the page itself asks for the admin token and calls the API.
func (h *Handler) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	if !h.admin.enabled {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
	w.Write(adminPage)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (h *Handler) handleAdminDevices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.tokens.List())
}

func (h *Handler) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	found, err := h.tokens.Revoke(id)
	if err != nil {
		http.Error(w, "revoke failed", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	h.record(audit.Entry{DeviceID: id, Event: audit.TokenRevoked, Status: http.StatusOK, IP: h.clientIP(r), Detail: "actor=admin"})
	w.WriteHeader(http.StatusOK)
}

// handleAdminEvents returns journal entries, newest first. Query params:
// device, event, exclude, since (RFC 3339), limit.
func (h *Handler) handleAdminEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := audit.Filter{DeviceID: q.Get("device"), Event: q.Get("event"), Exclude: q.Get("exclude")}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "invalid since (want RFC 3339)", http.StatusBadRequest)
			return
		}
		f.Since = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		f.Limit = n
	}
	if h.audit == nil {
		writeJSON(w, []audit.Entry{})
		return
	}
	entries, err := h.audit.Query(f)
	if err != nil {
		http.Error(w, "journal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, entries)
}

// handleAdminStats returns polling request counts per device, kind and hour
// over the last 24 hours (or ?since=). Pending in-memory tallies are
// flushed first so recent activity shows up.
func (h *Handler) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-adminStatsWindow)
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "invalid since (want RFC 3339)", http.StatusBadRequest)
			return
		}
		since = t
	}
	if h.audit == nil {
		writeJSON(w, []audit.StatRow{})
		return
	}
	if err := h.audit.Flush(); err != nil {
		http.Error(w, "journal error", http.StatusInternalServerError)
		return
	}
	rows, err := h.audit.Stats(since)
	if err != nil {
		http.Error(w, "journal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, rows)
}
