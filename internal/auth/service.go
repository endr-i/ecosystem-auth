package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/endr-i/ecosystem-auth/internal/keys"
	"github.com/endr-i/ecosystem-auth/internal/user"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrValidation         = errors.New("validation error")

	// E.164-ish: optional +, 7-15 digits.
	phoneRe = regexp.MustCompile(`^\+?[1-9][0-9]{6,14}$`)
)

type Config struct {
	Keys            *keys.Set
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	BcryptCost      int
}

type Service struct {
	cfg   Config
	users *user.Repository
	pool  *pgxpool.Pool
}

func NewService(cfg Config, users *user.Repository, pool *pgxpool.Pool) *Service {
	if cfg.BcryptCost == 0 {
		cfg.BcryptCost = bcrypt.DefaultCost
	}
	return &Service{cfg: cfg, users: users, pool: pool}
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

func validationError(msg string) error {
	return fmt.Errorf("%w: %s", ErrValidation, msg)
}

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func ValidateRegistration(email, password, phone string) error {
	if _, err := mail.ParseAddress(email); err != nil || email == "" {
		return validationError("invalid email address")
	}
	if len(password) < 8 {
		return validationError("password must be at least 8 characters")
	}
	if len(password) > 72 {
		return validationError("password must be at most 72 characters")
	}
	if !phoneRe.MatchString(strings.ReplaceAll(phone, " ", "")) {
		return validationError("invalid phone number, expected E.164 format like +15551234567")
	}
	return nil
}

func (s *Service) Register(ctx context.Context, email, password, phone string) (*user.User, error) {
	email = NormalizeEmail(email)
	phone = strings.ReplaceAll(strings.TrimSpace(phone), " ", "")
	if err := ValidateRegistration(email, password, phone); err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	return s.users.Create(ctx, email, string(hash), phone)
}

func (s *Service) Login(ctx context.Context, email, password string) (*user.User, *TokenPair, error) {
	email = NormalizeEmail(email)
	u, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			// Burn time to reduce user-enumeration timing signal.
			_ = bcrypt.CompareHashAndPassword(
				[]byte("$2a$12$C6UzMDM.H6dfI/f/IKcEeO7bYtGYFOWJmSxpJTIVdLQnPXk8Kq0d6"),
				[]byte(password))
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, nil, ErrInvalidCredentials
	}
	pair, err := s.issueTokens(ctx, u.ID)
	if err != nil {
		return nil, nil, err
	}
	return u, pair, nil
}

// Refresh rotates the refresh token: the presented token is revoked and a new
// pair is issued.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	hash := hashToken(refreshToken)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var userID string
	err = tx.QueryRow(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
		RETURNING user_id`, hash).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return s.issueTokens(ctx, userID)
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL`, hashToken(refreshToken))
	return err
}

func (s *Service) newAccessClaims(userID string) *jwt.RegisteredClaims {
	now := time.Now()
	return &jwt.RegisteredClaims{
		Subject:   userID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessTokenTTL)),
		Issuer:    "ecosystem-auth",
	}
}

func (s *Service) signAccessToken(claims *jwt.RegisteredClaims) (string, error) {
	key := s.cfg.Keys.Active()
	if key == nil {
		return "", errors.New("no active signing key")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.ID
	return token.SignedString(key.Private)
}

// JWKS returns the public keys other services use to verify issued tokens.
func (s *Service) JWKS() keys.JWKS {
	return s.cfg.Keys.JWKS()
}

func (s *Service) issueTokens(ctx context.Context, userID string) (*TokenPair, error) {
	now := time.Now()
	access, err := s.signAccessToken(s.newAccessClaims(userID))
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}
	refresh := base64.RawURLEncoding.EncodeToString(raw)

	_, err = s.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)`,
		userID, hashToken(refresh), now.Add(s.cfg.RefreshTokenTTL))
	if err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.cfg.AccessTokenTTL.Seconds()),
	}, nil
}

// VerifyAccessToken validates the JWT and returns the user ID (subject).
func (s *Service) VerifyAccessToken(tokenStr string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
			}
			kid, _ := t.Header["kid"].(string)
			if kid == "" {
				return nil, errors.New("token is missing a kid header")
			}
			return s.cfg.Keys.Lookup(kid)
		}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !token.Valid {
		return "", ErrInvalidToken
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || claims.Subject == "" {
		return "", ErrInvalidToken
	}
	return claims.Subject, nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
