package lab

import (
	"encoding/base64"
	"testing"
)

func TestGenerateWGKeyPair(t *testing.T) {
	kp1, err := GenerateWGKeyPair()
	if err != nil {
		t.Fatalf("GenerateWGKeyPair() unexpected error: %v", err)
	}
	kp2, err := GenerateWGKeyPair()
	if err != nil {
		t.Fatalf("GenerateWGKeyPair() unexpected error: %v", err)
	}

	if kp1.PrivateKey == kp2.PrivateKey || kp1.PublicKey == kp2.PublicKey {
		t.Fatalf("expected distinct key pairs, got identical keys")
	}

	privBytes, err := base64.StdEncoding.DecodeString(kp1.PrivateKey)
	if err != nil || len(privBytes) != 32 {
		t.Fatalf("expected 32-byte base64 private key, got len=%d err=%v", len(privBytes), err)
	}

	pubBytes, err := base64.StdEncoding.DecodeString(kp1.PublicKey)
	if err != nil || len(pubBytes) != 32 {
		t.Fatalf("expected 32-byte base64 public key, got len=%d err=%v", len(pubBytes), err)
	}
}
