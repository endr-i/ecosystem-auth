// Package keys loads RSA signing keys used to issue RS256 JWTs and exposes
// their public halves as a JWKS document.
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// KeySize is the modulus size used for generated keys.
const KeySize = 2048

var (
	ErrNoKeys      = errors.New("no signing keys found")
	ErrUnknownKID  = errors.New("unknown key id")
	ErrKIDNotFound = errors.New("active key id not found in key set")
)

// Key is a single RSA signing key identified by its kid.
type Key struct {
	ID      string
	Private *rsa.PrivateKey
}

// Set holds every key trusted for verification plus the one currently used
// for signing.
type Set struct {
	keys   map[string]*Key
	active *Key
	order  []string
}

// Load reads every *.pem file in dir as a PKCS#8/PKCS#1 RSA private key. The
// file name without its extension becomes the key id. When activeKID is empty
// the lexically greatest key id is used for signing, which makes date-based
// ids such as key-2026-09 rotate naturally.
func Load(dir, activeKID string) (*Set, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		return nil, fmt.Errorf("scan key dir %s: %w", dir, err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w in %s", ErrNoKeys, dir)
	}
	sort.Strings(matches)

	set := &Set{keys: make(map[string]*Key, len(matches))}
	for _, path := range matches {
		base := filepath.Base(path)
		// Companion public keys written by cmd/keygen are not signing keys.
		if strings.HasSuffix(base, ".pub.pem") {
			continue
		}
		kid := strings.TrimSuffix(base, ".pem")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read key %s: %w", path, err)
		}
		priv, err := ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse key %s: %w", path, err)
		}
		set.keys[kid] = &Key{ID: kid, Private: priv}
		set.order = append(set.order, kid)
	}

	if len(set.order) == 0 {
		return nil, fmt.Errorf("%w in %s", ErrNoKeys, dir)
	}

	if activeKID != "" {
		k, ok := set.keys[activeKID]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrKIDNotFound, activeKID)
		}
		set.active = k
	} else {
		set.active = set.keys[set.order[len(set.order)-1]]
	}
	return set, nil
}

// NewSet builds a Set from in-memory keys; the first key signs. Useful in tests.
func NewSet(keys ...*Key) *Set {
	set := &Set{keys: make(map[string]*Key, len(keys))}
	for _, k := range keys {
		set.keys[k.ID] = k
		set.order = append(set.order, k.ID)
	}
	if len(keys) > 0 {
		set.active = keys[0]
	}
	return set
}

// Active returns the key used to sign newly issued tokens.
func (s *Set) Active() *Key { return s.active }

// Lookup returns the public key for kid, for signature verification.
func (s *Set) Lookup(kid string) (*rsa.PublicKey, error) {
	k, ok := s.keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKID, kid)
	}
	return &k.Private.PublicKey, nil
}

// JWK is a single public key in JWKS form.
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is the document served at /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS returns the public half of every key in the set.
func (s *Set) JWKS() JWKS {
	out := JWKS{Keys: make([]JWK, 0, len(s.order))}
	for _, kid := range s.order {
		pub := &s.keys[kid].Private.PublicKey
		out.Keys = append(out.Keys, JWK{
			Kid: kid,
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	return out
}

// Generate creates a new RSA private key.
func Generate() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, KeySize)
}

// EncodePrivateKey renders key as a PKCS#8 PEM block.
func EncodePrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// EncodePublicKey renders the public half of key as a PKIX PEM block.
func EncodePublicKey(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePrivateKey decodes a PKCS#8 or PKCS#1 RSA private key in PEM form.
func ParsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		priv, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected an RSA key, got %T", parsed)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}
