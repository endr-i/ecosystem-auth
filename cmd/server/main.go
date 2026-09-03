package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	authv1 "github.com/endr-i/ecosystem-auth/gen/auth/v1"
	"github.com/endr-i/ecosystem-auth/internal/auth"
	"github.com/endr-i/ecosystem-auth/internal/config"
	"github.com/endr-i/ecosystem-auth/internal/db"
	"github.com/endr-i/ecosystem-auth/internal/grpcapi"
	"github.com/endr-i/ecosystem-auth/internal/httpapi"
	"github.com/endr-i/ecosystem-auth/internal/keys"
	"github.com/endr-i/ecosystem-auth/internal/ratelimit"
	"github.com/endr-i/ecosystem-auth/internal/user"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("database connect", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		log.Error("migrate", "err", err)
		os.Exit(1)
	}

	keySet, err := keys.Load(cfg.JWTKeysDir, cfg.JWTActiveKID)
	if err != nil {
		log.Error("load signing keys", "err", err, "dir", cfg.JWTKeysDir)
		os.Exit(1)
	}
	log.Info("signing keys loaded", "dir", cfg.JWTKeysDir, "active_kid", keySet.Active().ID)

	users := user.NewRepository(pool)
	authSvc := auth.NewService(auth.Config{
		Keys:            keySet,
		AccessTokenTTL:  cfg.AccessTokenTTL,
		RefreshTokenTTL: cfg.RefreshTokenTTL,
		BcryptCost:      cfg.BcryptCost,
	}, users, pool)

	redisOpts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Error("parse redis url", "err", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(redisOpts)
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Error("redis connect", "err", err)
		os.Exit(1)
	}
	limiter := ratelimit.NewLimiter(rdb)
	policy := ratelimit.DefaultPolicy()

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           httpapi.NewServer(authSvc, users, log, limiter, policy).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	grpcSrv := grpc.NewServer(grpc.UnaryInterceptor(limiter.UnaryInterceptor(policy, log)))
	authv1.RegisterAuthServiceServer(grpcSrv, grpcapi.NewServer(authSvc, users, log))
	healthv1.RegisterHealthServer(grpcSrv, health.NewServer())
	reflection.Register(grpcSrv)

	go func() {
		log.Info("http listening", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server", "err", err)
			stop()
		}
	}()

	go func() {
		lis, err := net.Listen("tcp", ":"+cfg.GRPCPort)
		if err != nil {
			log.Error("grpc listen", "err", err)
			stop()
			return
		}
		log.Info("grpc listening", "port", cfg.GRPCPort)
		if err := grpcSrv.Serve(lis); err != nil {
			log.Error("grpc server", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	grpcSrv.GracefulStop()
}
