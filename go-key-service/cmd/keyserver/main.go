package main

import (
<<<<<<< HEAD
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
=======
	"fmt"
	"log"
	"net/http"
>>>>>>> f1c2c79 (Ed25519 keypair generation & registration API)

	"github.com/gorilla/mux"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
<<<<<<< HEAD
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/config"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/httpapi"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/keystore"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)
	logger.Info("starting", "addr", cfg.Addr, "schema_version", action.SchemaVersion)

	store := keystore.NewMemory()
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           httpapi.NewServer(store, logger).Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-stop:
		logger.Info("shutting down", "signal", sig.String())
	case err := <-errCh:
		logger.Error("server", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("shutdown", "err", err)
		os.Exit(1)
	}
=======
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/keys"
)

func main() {
	fmt.Printf("CryptoAgent key-service (schema v%d) listening on :8080\n", action.SchemaVersion)
	r := mux.NewRouter()
	keys.RegisterRoutes(r, keys.NewMemoryStore())
	log.Fatal(http.ListenAndServe(":8080", r))
>>>>>>> f1c2c79 (Ed25519 keypair generation & registration API)
}
