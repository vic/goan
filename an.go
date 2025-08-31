package goan

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"time"
)

// Gen returns base64(publicKey)+base64(secretKey)
func Gen() (string, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", err
	}
	pubB := base64.StdEncoding.EncodeToString(pub)
	privB := base64.StdEncoding.EncodeToString(priv)
	return pubB + privB, nil
}

func Hash(d string) string {
	h := sha256.Sum256([]byte(d))
	return base64.StdEncoding.EncodeToString(h[:])
}

func Sign(h string, k string) (string, error) {
	if len(k) < 44+88 {
		return "", errors.New("invalid key length")
	}
	pubB := k[:44]
	privB := k[44:]
	priv, err := base64.StdEncoding.DecodeString(privB)
	if err != nil {
		return "", err
	}
	msg := []byte(strconv.FormatInt(time.Now().UnixNano()/1e6, 10) + h)
	sig := ed25519.Sign(priv, msg)
	signed := append(sig, msg...)
	signedB := base64.StdEncoding.EncodeToString(signed)
	return pubB + signedB, nil
}

func Open(m string) (string, error) {
	if len(m) < 44 {
		return "", errors.New("invalid message")
	}
	pubB := m[:44]
	signedB := m[44:]
	signed, err := base64.StdEncoding.DecodeString(signedB)
	if err != nil {
		return "", err
	}
	if len(signed) < ed25519.SignatureSize {
		return "", errors.New("signed message too short")
	}
	sig := signed[:ed25519.SignatureSize]
	msg := signed[ed25519.SignatureSize:]
	pub, err := base64.StdEncoding.DecodeString(pubB)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return "", errors.New("signature verification failed")
	}
	return string(msg), nil
}
