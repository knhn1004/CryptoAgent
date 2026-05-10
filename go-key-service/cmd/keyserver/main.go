package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/anchor"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/auditlog"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/capability"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/config"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/httpapi"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/keystore"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/merkle"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)
	logger.Info("starting", "addr", cfg.Addr, "schema_version", action.SchemaVersion, "anchor_mode", cfg.AnchorMode)

	store := keystore.NewMemory()
	tree := merkle.New()
	pipeline := auditlog.New(tree, store)
	capSvc, err := capability.NewService(store, capability.Options{
		Logger:        logger,
		RejectionSink: pipeline.RecordRejection,
	})
	if err != nil {
		logger.Error("capability", "err", err)
		os.Exit(1)
	}

	apiServer := httpapi.NewServer(store, logger).
		WithAuditPipeline(pipeline).
		WithCapability(capSvc).
		WithMerkleTree(tree).
		WithCORS(cfg.CORSOrigins)

	var committer *anchor.Committer
	if cfg.AnchorMode != config.AnchorOff {
		client, err := buildAnchorClient(cfg)
		if err != nil {
			logger.Error("anchor client", "err", err)
			os.Exit(1)
		}
		latest := anchor.NewLatestStore()
		committer, err = anchor.NewCommitter(tree, client, latest, anchor.CommitterOptions{
			Interval: cfg.AnchorInterval,
			Logger:   logger,
		})
		if err != nil {
			logger.Error("anchor committer", "err", err)
			os.Exit(1)
		}
		apiServer = apiServer.WithAnchor(latest)
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           apiServer.Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	if committer != nil {
		committer.Start(context.Background())
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

	if committer != nil {
		if !committer.Stop(5 * time.Second) {
			logger.Warn("anchor committer did not stop cleanly")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("shutdown", "err", err)
		os.Exit(1)
	}
}

func buildAnchorClient(cfg config.Config) (anchor.EVMClient, error) {
	switch cfg.AnchorMode {
	case config.AnchorDryRun:
		return anchor.NewFakeEVMClient(), nil
	case config.AnchorCast:
		return anchor.NewCastClient(anchor.CastClientConfig{
			ContractAddress: cfg.AnchorContractAddress,
			RPCURL:          cfg.AnchorRPCURL,
			PrivateKey:      cfg.AnchorPrivateKey.Reveal(),
			CastBinary:      cfg.AnchorCastBinary,
		})
	default:
		return nil, errors.New("buildAnchorClient: unsupported anchor mode")
	}
}
