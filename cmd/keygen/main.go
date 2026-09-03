// Command keygen writes a new RSA private key for signing RS256 access tokens.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/endr-i/ecosystem-auth/internal/keys"
)

func main() {
	dir := flag.String("dir", "keys", "directory to write the key into")
	kid := flag.String("kid", "", "key id; defaults to key-YYYY-MM")
	force := flag.Bool("force", false, "overwrite an existing key with the same id")
	flag.Parse()

	if *kid == "" {
		*kid = "key-" + time.Now().UTC().Format("2006-01")
	}
	if filepath.Base(*kid) != *kid {
		fail(fmt.Errorf("kid %q must not contain path separators", *kid))
	}

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fail(err)
	}

	privPath := filepath.Join(*dir, *kid+".pem")
	pubPath := filepath.Join(*dir, *kid+".pub.pem")
	if _, err := os.Stat(privPath); err == nil && !*force {
		fail(fmt.Errorf("%s already exists; pass -force to overwrite", privPath))
	}

	key, err := keys.Generate()
	if err != nil {
		fail(err)
	}
	privPEM, err := keys.EncodePrivateKey(key)
	if err != nil {
		fail(err)
	}
	pubPEM, err := keys.EncodePublicKey(key)
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		fail(err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		fail(err)
	}

	fmt.Printf("wrote %s (kid=%s)\nwrote %s\n", privPath, *kid, pubPath)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "keygen:", err)
	os.Exit(1)
}
