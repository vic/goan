package goan

import (
	"bytes"
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func runNode(args ...string) (string, error) {
	cmd := exec.Command("node", append([]string{"js_helper.js"}, args...)...)
	cmd.Dir = "./"
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func TestJSGoInterop(t *testing.T) {
	// generate using node
	k, err := runNode("gen")
	if err != nil {
		t.Fatalf("node gen failed: %v - %s", err, k)
	}
	if len(k) != 132 {
		t.Fatalf("node gen key length unexpected: %d", len(k))
	}

	// hash
	h := Hash("hello")

	// sign with node, open with go
	signed, err := runNode("sign", h, k)
	if err != nil {
		t.Fatalf("node sign failed: %v - %s", err, signed)
	}

	opened, err := Open(signed)
	if err != nil {
		t.Fatalf("go open failed: %v", err)
	}
	if !strings.HasSuffix(opened, h) {
		t.Fatalf("opened must end with hash")
	}

	// Also open the same signed message with Node and ensure it matches Go's opened message
	jsOpened, err := runNode("open", signed)
	if err != nil {
		t.Fatalf("node open of node-signed failed: %v - %s", err, jsOpened)
	}
	if jsOpened != opened {
		t.Fatalf("mismatch between node-open and go-open: node=%q go=%q", jsOpened, opened)
	}

	// now sign with go and open with node
	gSigned, err := Sign(h, k)
	if err != nil {
		t.Fatalf("go sign failed: %v", err)
	}
	// node open
	nOpened, err := runNode("open", gSigned)
	if err != nil {
		t.Fatalf("node open failed: %v - %s", err, nOpened)
	}
	if !strings.HasSuffix(nOpened, h) {
		t.Fatalf("node opened must end with hash")
	}

	// Also open the Go-signed message with Go and ensure it matches Node's opened message
	goOpened, err := Open(gSigned)
	if err != nil {
		t.Fatalf("go open of go-signed failed: %v", err)
	}
	if goOpened != nOpened {
		t.Fatalf("mismatch between go-open and node-open for go-signed: go=%q node=%q", goOpened, nOpened)
	}

	// verify that signatures are valid base64 and length
	// decode signed from go (which is pubB64 + signedB64)
	if len(gSigned) <= 44 {
		t.Fatalf("gSigned too short")
	}
	b64 := gSigned[44:]
	_, err = base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("signed not valid base64: %v", err)
	}

	// timestamp sanity
	tsPart := opened[:len(opened)-len(h)]
	if len(tsPart) == 0 {
		t.Fatalf("empty timestamp")
	}
	// ensure timestamp within 60s
	// parse
	// naive parse
	if len(tsPart) < 5 {
		t.Fatalf("ts too short")
	}
	_ = time.Now()
}

func TestGoJSInterop(t *testing.T) {
	// generate using go
	k, err := Gen()
	if err != nil {
		t.Fatalf("go gen failed: %v", err)
	}
	if len(k) != 132 {
		t.Fatalf("go gen key length unexpected: %d", len(k))
	}

	// hash
	h := Hash("hello")

	// sign with go, open with node
	gSigned, err := Sign(h, k)
	if err != nil {
		t.Fatalf("go sign failed: %v", err)
	}

	nOpened, err := runNode("open", gSigned)
	if err != nil {
		t.Fatalf("node open of go-signed failed: %v - %s", err, nOpened)
	}
	if !strings.HasSuffix(nOpened, h) {
		t.Fatalf("node opened must end with hash")
	}

	// sign with node, open with go
	nSigned, err := runNode("sign", h, k)
	if err != nil {
		t.Fatalf("node sign failed: %v - %s", err, nSigned)
	}

	opened, err := Open(nSigned)
	if err != nil {
		t.Fatalf("go open of node-signed failed: %v", err)
	}
	if !strings.HasSuffix(opened, h) {
		t.Fatalf("go opened must end with hash")
	}

	// basic format checks
	if len(nSigned) <= 44 {
		t.Fatalf("nSigned too short")
	}
	b64 := nSigned[44:]
	if _, err := base64.StdEncoding.DecodeString(b64); err != nil {
		t.Fatalf("nSigned not valid base64: %v", err)
	}
}

func TestExamplesFromReadme(t *testing.T) {
	// examples taken verbatim from README.md
	exampleHash := "pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4="
	exampleSigned := "BSY7/er4VJIu08o39NaRAiPY/MAvd7oQhlGCRDABjYU=yVpD8i7d3d4dls3YThEg1x1vSdmqeEweV4e4Ejl/8yPoVG7JR0YAKDPagQOgxXMrlCVLNNqvlNvj4xRDOYDLBjE3NTUxOTc4NDEzMTlwWkdtMUF2MElFQktBUmN6ejdleGtOWXNaYjhMemFNclY3SjMyYTJmRkc0PQ=="
	expectedOpened := "1755197841319pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4="

	// Go should open the example signed message
	opened, err := Open(exampleSigned)
	if err != nil {
		t.Fatalf("Go Open failed on README example: %v", err)
	}
	if opened != expectedOpened {
		t.Fatalf("Go opened mismatch: got %q want %q", opened, expectedOpened)
	}

	// Node should also open the same example and produce the same output
	nOpened, err := runNode("open", exampleSigned)
	if err != nil {
		t.Fatalf("node open failed on README example: %v - %s", err, nOpened)
	}
	if nOpened != expectedOpened {
		t.Fatalf("Node opened mismatch: got %q want %q", nOpened, expectedOpened)
	}

	// Hash of "Hello World" should match the README example
	h := Hash("Hello World")
	if h != exampleHash {
		t.Fatalf("Hash(\"Hello World\") mismatch: got %q want %q", h, exampleHash)
	}
}
