package keys

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func writeKey(t *testing.T, dir, kid string) *rsa.PrivateKey {
	t.Helper()
	key, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := EncodePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := EncodePublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, kid+".pem"), privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, kid+".pub.pem"), pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestLoadPicksNewestKID(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "key-2026-08")
	writeKey(t, dir, "key-2026-09")

	set, err := Load(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := set.Active().ID; got != "key-2026-09" {
		t.Fatalf("active kid = %q, want key-2026-09", got)
	}
	if _, err := set.Lookup("key-2026-08"); err != nil {
		t.Fatalf("old key should still verify: %v", err)
	}
	if _, err := set.Lookup("key-2026-09.pub"); err == nil {
		t.Fatal("public key file must not be loaded as a signing key")
	}
}

func TestLoadExplicitKID(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "key-a")
	writeKey(t, dir, "key-b")

	set, err := Load(dir, "key-a")
	if err != nil {
		t.Fatal(err)
	}
	if got := set.Active().ID; got != "key-a" {
		t.Fatalf("active kid = %q, want key-a", got)
	}
	if _, err := Load(dir, "missing"); err == nil {
		t.Fatal("expected error for unknown active kid")
	}
}

func TestLoadEmptyDir(t *testing.T) {
	if _, err := Load(t.TempDir(), ""); err == nil {
		t.Fatal("expected ErrNoKeys for an empty directory")
	}
}

func TestJWKSMatchesKey(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, "key-2026-09")

	set, err := Load(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	jwks := set.JWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(jwks.Keys))
	}
	jwk := jwks.Keys[0]
	if jwk.Kid != "key-2026-09" || jwk.Kty != "RSA" || jwk.Use != "sig" || jwk.Alg != "RS256" {
		t.Fatalf("unexpected jwk metadata: %+v", jwk)
	}
	if jwk.E != "AQAB" {
		t.Fatalf("e = %q, want AQAB", jwk.E)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatal(err)
	}
	if new(big.Int).SetBytes(nBytes).Cmp(key.PublicKey.N) != 0 {
		t.Fatal("modulus in JWKS does not match the private key")
	}
}

func TestParsePrivateKeyRejectsGarbage(t *testing.T) {
	if _, err := ParsePrivateKey([]byte("not a pem")); err == nil {
		t.Fatal("expected error")
	}
}
