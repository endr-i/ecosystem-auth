package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	Port            string
	GRPCPort        string
	DatabaseURL     string
	RedisURL        string
	JWTKeysDir      string
	JWTActiveKID    string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	BcryptCost      int
}

func Load() (*Config, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	cfg := &Config{
		Port:            getEnv("PORT", "8080"),
		GRPCPort:        getEnv("GRPC_PORT", "9090"),
		DatabaseURL:     dbURL,
		RedisURL:        getEnv("REDIS_URL", "redis://localhost:6379/0"),
		JWTKeysDir:      getEnv("JWT_KEYS_DIR", "keys"),
		JWTActiveKID:    os.Getenv("JWT_ACTIVE_KID"),
		AccessTokenTTL:  getDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL: getDuration("REFRESH_TOKEN_TTL", 30*24*time.Hour),
		BcryptCost:      12,
	}
	return cfg, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
