package handler

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/changelog"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/sse"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/store"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/tokens"
)

// Handler is the HTTP handler for the obsidian-sync server.
// It wires together auth middleware, the changelog, file store, and SSE broker.
type Handler struct {
	store     *store.Store
	changelog *changelog.Changelog
	sse       *sse.Broker
	tokens    *tokens.Store
	mux       *http.ServeMux
}

// New constructs a Handler and registers all routes.
func New(s *store.Store, cl *changelog.Changelog, broker *sse.Broker, ts *tokens.Store) *Handler {
	h := &Handler{store: s, changelog: cl, sse: broker, tokens: ts}
	h.mux = http.NewServeMux()
	h.mux.HandleFunc("GET /changes", h.withAuth(h.handleChanges))
	h.mux.HandleFunc("GET /file/{path...}", h.withAuth(h.handleGetFile))
	h.mux.HandleFunc("PUT /file/{path...}", h.withAuth(h.handlePutFile))
	h.mux.HandleFunc("DELETE /file/{path...}", h.withAuth(h.handleDeleteFile))
	h.mux.HandleFunc("GET /events", h.withAuth(h.handleEvents))
	h.mux.HandleFunc("POST /pair", h.withAuth(h.handlePair))
	h.mux.HandleFunc("GET /devices", h.withAuth(h.handleListDevices))
	h.mux.HandleFunc("DELETE /devices/{id}", h.withAuth(h.handleRevokeDevice))
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, X-Base-Hash, Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rw := &statusRecorder{ResponseWriter: w, status: 200}
	h.mux.ServeHTTP(rw, r)
	log.Printf("%s %s %d", r.Method, r.URL.Path, rw.status)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// Flush forwards to the underlying writer so the wrapper preserves the
// http.Flusher interface. Without this, /events (SSE) fails its
// w.(http.Flusher) assertion and returns 500 "streaming unsupported".
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// withAuth wraps a handler with per-device bearer token authentication.
// EventSource clients (GET /events) may pass the token as ?token= query param
// since the browser EventSource API cannot set custom headers.
func (h *Handler) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// SSE clients (EventSource) cannot set headers; accept ?token= on /events.
		// If it's missing/invalid, fall through to the normal header check below
		// rather than failing immediately — /events also accepts a normal
		// Authorization header from non-EventSource callers.
		if r.URL.Path == "/events" {
			if _, ok := h.tokens.Verify(r.URL.Query().Get("token")); ok {
				next(w, r)
				return
			}
		}
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, ok := h.tokens.Verify(strings.TrimPrefix(auth, prefix)); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// handleChanges returns changelog entries newer than the given ?since= Unix timestamp.
func (h *Handler) handleChanges(w http.ResponseWriter, r *http.Request) {
	sinceStr := r.URL.Query().Get("since")
	since, _ := strconv.ParseInt(sinceStr, 10, 64)

	entries, err := h.changelog.Since(since)
	if err != nil {
		http.Error(w, "changelog error", http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []changelog.Entry{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func (h *Handler) handleGetFile(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	data, err := h.store.ReadFile(path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Write(data)
}

func (h *Handler) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	baseHash := r.Header.Get("X-Base-Hash")

	currentHash, exists := h.store.GetHash(path)
	if exists && currentHash != baseHash {
		http.Error(w, "hash mismatch", http.StatusConflict)
		return
	}

	if err := h.store.DeleteFile(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}

	_ = h.changelog.Append(changelog.Entry{TS: nowUnix(), Path: path, Action: "deleted"})
	h.sse.Publish(sse.Event{Path: path, Action: "deleted"})
}

func (h *Handler) handlePutFile(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	baseHash := r.Header.Get("X-Base-Hash")

	r.Body = http.MaxBytesReader(w, r.Body, 100<<20) // 100 MB cap
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request too large or unreadable", http.StatusBadRequest)
		return
	}

	currentHash, exists := h.store.GetHash(path)
	newHash := sha256hex(data)
	now := nowUnix()

	// Identical content already stored — no-op regardless of the base hash.
	// This must come before the conflict check: a stale/empty X-Base-Hash on a
	// byte-identical upload (the signature of a pull→push echo) would otherwise
	// spawn a bogus .conflict copy. Skipping the changelog append + SSE publish
	// here also breaks the re-upload loop at the source.
	if exists && currentHash == newHash {
		w.Header().Set("X-Conflict", "false")
		// Return the current canonical hash so the client can confirm its state
		// is up-to-date without a round-trip to /changes.
		w.Header().Set("X-Current-Hash", currentHash)
		return
	}

	if exists && currentHash != baseHash {
		conflictPath := conflictName(path)
		if err := h.store.WriteFile(conflictPath, data); err != nil {
			http.Error(w, "store conflict", http.StatusInternalServerError)
			return
		}
		_ = h.changelog.Append(changelog.Entry{TS: now, Path: conflictPath, Hash: newHash, Action: "modified"})
		h.sse.Publish(sse.Event{Path: conflictPath, Hash: newHash, Action: "modified"})
		w.Header().Set("X-Conflict", "true")
		// Return the server's current canonical hash so the client can update its
		// base-hash state immediately. Without this the client retains the stale
		// X-Base-Hash and every subsequent push hits this branch again, creating
		// an unbounded conflict-copy storm.
		w.Header().Set("X-Current-Hash", currentHash)
		return
	}

	if err := h.store.WriteFile(path, data); err != nil {
		http.Error(w, "store file", http.StatusInternalServerError)
		return
	}
	_ = h.changelog.Append(changelog.Entry{TS: now, Path: path, Hash: newHash, Action: "modified"})
	h.sse.Publish(sse.Event{Path: path, Hash: newHash, Action: "modified"})
	w.Header().Set("X-Conflict", "false")
	w.Header().Set("X-Current-Hash", newHash)
}

// conflictName derives the conflict copy path for the given file path.
// Example: "notes/foo.md" → "notes/foo.conflict.2006-01-02T15-04-05.md"
func conflictName(path string) string {
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	return base + ".conflict." + time.Now().Format("2006-01-02T15-04-05.000000000") + ext
}

// sha256hex returns the hex-encoded SHA-256 digest of data.
func sha256hex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

func (h *Handler) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsub := h.sse.Subscribe()
	defer unsub()

	// Flush an initial comment so the client receives the response head
	// immediately and EventSource fires onopen, rather than waiting (and
	// possibly timing out behind nginx) for the first real change.
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	// Heartbeat keeps the connection alive through idle proxy read timeouts
	// (nginx-ingress defaults to 60s); an SSE comment is ignored by the client.
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case event, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// handlePair issues a new device token. Any already-authenticated device
// may call this; there is no separate admin credential.
func (h *Handler) handlePair(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	label := strings.TrimSpace(body.Label)
	if label == "" {
		label = "unnamed device"
	}
	id, token, err := h.tokens.Issue(label)
	if err != nil {
		http.Error(w, "issue failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": id, "token": token})
}

// handleListDevices returns every paired device, without token hashes.
func (h *Handler) handleListDevices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.tokens.List())
}

// handleRevokeDevice revokes the device with the given id. Any
// authenticated device may revoke any device, including itself.
func (h *Handler) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
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
	w.WriteHeader(http.StatusOK)
}

// nowUnix returns the current time as a Unix timestamp.
// Declared here for use by T6/T7 file-mutation handlers.
func nowUnix() int64 { return time.Now().Unix() }


