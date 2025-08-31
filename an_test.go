package goan

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestGenHashSignOpen(t *testing.T) {
	k, err := Gen()
	if err != nil {
		t.Fatalf("Gen error: %v", err)
	}
	if len(k) != 132 {
		t.Fatalf("expected key length 132 got %d", len(k))
	}

	// verify hash function still works
	h := Hash("hello")
	exph := sha256.Sum256([]byte("hello"))
	expb64 := base64.StdEncoding.EncodeToString(exph[:])
	if h != expb64 {
		t.Fatalf("hash mismatch")
	}

	// Sign the plain text message "hello" (not its hash)
	signed, err := Sign("hello", k)
	if err != nil {
		t.Fatalf("sign error: %v", err)
	}
	if signed[:44] != k[:44] {
		t.Fatalf("signed must start with pub key")
	}

	opened, err := Open(signed)
	if err != nil {
		t.Fatalf("open error: %v", err)
	}
	// For compatibility with example.js, the test strips the first 13 bytes (timestamp)
	if len(opened) < 13 {
		t.Fatalf("opened too short to strip timestamp")
	}
	payload := opened[13:]
	if payload != "hello" {
		t.Fatalf("opened payload must equal 'hello', got: %q", payload)
	}
}
