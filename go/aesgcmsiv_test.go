package aesgcmsiv_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	aesgcmsiv "github.com/line/aes-gcm-siv/go"
)

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func testVectors(t *testing.T, vectors []struct {
	plaintext, aad, key, nonce, out string
}) {
	t.Helper()
	for i, vector := range vectors {
		key := decodeHex(t, vector.key)
		nonce := decodeHex(t, vector.nonce)
		plaintext := decodeHex(t, vector.plaintext)
		aad := decodeHex(t, vector.aad)
		want := decodeHex(t, vector.out)

		cipher, err := aesgcmsiv.NewAesGcmSiv(key)
		if err != nil {
			t.Fatalf("vector %d: new cipher: %v", i, err)
		}
		got, err := cipher.Seal(nonce, plaintext, aad)
		if err != nil {
			cipher.FreeAesGcmSiv()
			t.Fatalf("vector %d: seal: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			cipher.FreeAesGcmSiv()
			t.Errorf("vector %d: ciphertext = %x, want %x", i, got, want)
			continue
		}
		opened, err := cipher.Open(nonce, want, aad)
		if err != nil {
			cipher.FreeAesGcmSiv()
			t.Fatalf("vector %d: open: %v", i, err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("vector %d: plaintext = %x, want %x", i, opened, plaintext)
		}
		cipher.FreeAesGcmSiv()
	}
}

func TestRFC8452Vectors128(t *testing.T) {
	testVectors(t, aes128GcmSivVectors)
}

func TestRFC8452Vectors256(t *testing.T) {
	testVectors(t, aes256GcmSivVectors)
}

func TestInvalidInputsAndAuthentication(t *testing.T) {
	if _, err := aesgcmsiv.NewAesGcmSiv(nil); err == nil {
		t.Fatal("empty key accepted")
	}
	cipher, err := aesgcmsiv.NewAesGcmSiv(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cipher.Seal(nil, nil, nil); err == nil {
		t.Error("empty nonce accepted")
	}
	if _, err := cipher.Open(make([]byte, cipher.NonceSize()), nil, nil); err == nil {
		t.Error("empty ciphertext accepted")
	}
	nonce := make([]byte, cipher.NonceSize())
	sealed, err := cipher.Seal(nonce, []byte("message"), nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed[0] ^= 1
	if _, err := cipher.Open(nonce, sealed, nil); err == nil {
		t.Error("modified ciphertext accepted")
	}
	cipher.FreeAesGcmSiv()
	if _, err := cipher.Seal(nonce, nil, nil); err == nil {
		t.Error("freed cipher accepted")
	}
	var nilCipher *aesgcmsiv.Aesgcmsiv
	if _, err := nilCipher.Open(nonce, sealed, nil); err == nil {
		t.Error("nil cipher accepted")
	}
}
