package httpapi

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/endr-i/ecosystem-auth/internal/auth"
	"github.com/endr-i/ecosystem-auth/internal/keys"
)

func TestJWKSEndpoint(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set := keys.NewSet(&keys.Key{ID: "key-2026-09", Private: priv})
	svc := auth.NewService(auth.Config{Keys: set, AccessTokenTTL: time.Minute}, nil, nil)
	srv := NewServer(svc, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var doc keys.JWKS
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(doc.Keys))
	}
	if doc.Keys[0].Kid != "key-2026-09" || doc.Keys[0].Alg != "RS256" {
		t.Fatalf("unexpected key: %+v", doc.Keys[0])
	}
	if doc.Keys[0].N == "" {
		t.Fatal("modulus is empty")
	}
}
