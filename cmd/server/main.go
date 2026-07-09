package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/changelog"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/handler"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/sse"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/store"
	"github.com/PeoneEr/self-hosted-vault-sync-server/internal/tokens"
)

func main() {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "/data"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	vaultDir := filepath.Join(dataDir, "vault")
	if err := os.MkdirAll(vaultDir, 0755); err != nil {
		log.Fatal(err)
	}

	tokenStore, err := tokens.New(filepath.Join(dataDir, "tokens.json"))
	if err != nil {
		log.Fatal(err)
	}
	// BOOTSTRAP_TOKEN is optional: set it to seed a known first-device token
	// (e.g. from Vault, for a reproducible deploy). If unset and no tokens
	// exist yet, a random one is generated and logged once below — that log
	// line is the only place it's ever shown.
	if raw, created, err := tokenStore.Bootstrap(os.Getenv("BOOTSTRAP_TOKEN")); err != nil {
		log.Fatal(err)
	} else if created {
		log.Printf("bootstrap device token (save this now — it will not be shown again): %s", raw)
	}

	s := store.New(vaultDir)
	cl := changelog.New(filepath.Join(dataDir, "changelog.jsonl"))
	broker := sse.NewBroker()
	h := handler.New(s, cl, broker, tokenStore)

	srv := &http.Server{
		Addr:        ":" + port,
		Handler:     h,
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 120 * time.Second,
		// No WriteTimeout — would terminate SSE streams
	}
	log.Printf("obsidian-sync listening on :%s", port)
	log.Fatal(srv.ListenAndServe())
}
