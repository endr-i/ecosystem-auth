package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/endr-i/ecosystem-auth/internal/keys"
	"github.com/endr-i/ecosystem-auth/internal/user"
)

func TestValidateRegistration(t *testing.T) {
	cases := []struct {
		name                   string
		email, password, phone string
		wantErr                bool
	}{
		{"valid", "a@example.com", "password123", "+15551234567", false},
		{"valid no plus", "a@example.com", "password123", "15551234567", false},
		{"bad email", "not-an-email", "password123", "+15551234567", true},
		{"empty email", "", "password123", "+15551234567", true},
		{"short password", "a@example.com", "short", "+15551234567", true},
		{"missing phone", "a@example.com", "password123", "", true},
		{"bad phone", "a@example.com", "password123", "abc123", true},
		{"phone leading zero", "a@example.com", "password123", "+05551234567", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRegistration(tc.email, tc.password, tc.phone)
			if (err != nil) != tc.wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestNormalizeEmail(t *testing.T) {
	if got := NormalizeEmail("  User@Example.COM "); got != "user@example.com" {
		t.Fatalf("got %q", got)
	}
}

func newTestKeySet(t *testing.T, kid string) *keys.Set {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return keys.NewSet(&keys.Key{ID: kid, Private: priv})
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	return NewService(Config{
		Keys:            newTestKeySet(t, "test-key"),
		AccessTokenTTL:  time.Minute,
		RefreshTokenTTL: time.Hour,
		BcryptCost:      4,
	}, (*user.Repository)(nil), (*pgxpool.Pool)(nil))
}

func TestVerifyAccessToken(t *testing.T) {
	s := newTestService(t)

	claims := s.newAccessClaims("user-123")
	token, err := s.signAccessToken(claims)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := s.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if sub != "user-123" {
		t.Fatalf("got subject %q", sub)
	}

	if _, err := s.VerifyAccessToken("garbage"); err == nil {
		t.Fatal("expected error for garbage token")
	}

	other := NewService(Config{Keys: newTestKeySet(t, "test-key"), AccessTokenTTL: time.Minute}, nil, nil)
	if _, err := other.VerifyAccessToken(token); err == nil {
		t.Fatal("expected error for token signed by a different key")
	}

	unknownKID := NewService(Config{Keys: newTestKeySet(t, "other-key"), AccessTokenTTL: time.Minute}, nil, nil)
	if _, err := unknownKID.VerifyAccessToken(token); err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

func TestAccessTokenHeader(t *testing.T) {
	s := newTestService(t)
	token, err := s.signAccessToken(s.newAccessClaims("user-123"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(token, &jwt.RegisteredClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Header["alg"]; got != "RS256" {
		t.Fatalf("alg = %v, want RS256", got)
	}
	if got := parsed.Header["kid"]; got != "test-key" {
		t.Fatalf("kid = %v, want test-key", got)
	}
}

func TestRejectsHS256Token(t *testing.T) {
	s := newTestService(t)
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, s.newAccessClaims("user-123"))
	forged.Header["kid"] = "test-key"
	// A confused-deputy attempt: HMAC the token with the public modulus.
	signed, err := forged.SignedString([]byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAccessToken(signed); err == nil {
		t.Fatal("expected HS256 token to be rejected")
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	s := newTestService(t)
	claims := s.newAccessClaims("user-123")
	claims.ExpiresAt.Time = time.Now().Add(-time.Hour)
	token, err := s.signAccessToken(claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAccessToken(token); err == nil {
		t.Fatal("expected error for expired token")
	}
}
