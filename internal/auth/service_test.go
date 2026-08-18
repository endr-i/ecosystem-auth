package auth

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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

func newTestService() *Service {
	return NewService(Config{
		JWTSecret:       []byte("test-secret"),
		AccessTokenTTL:  time.Minute,
		RefreshTokenTTL: time.Hour,
		BcryptCost:      4,
	}, (*user.Repository)(nil), (*pgxpool.Pool)(nil))
}

func TestVerifyAccessToken(t *testing.T) {
	s := newTestService()

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

	other := NewService(Config{JWTSecret: []byte("other-secret"), AccessTokenTTL: time.Minute}, nil, nil)
	if _, err := other.VerifyAccessToken(token); err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	s := newTestService()
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
