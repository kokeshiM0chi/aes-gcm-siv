package aesgcmsiv

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRFC8452Vectors(t *testing.T) {
	for _, vectors := range []struct {
		name string
		list []struct{ plaintext, aad, key, nonce, out string }
	}{
		{"AES-128", aes128GcmSivVectors},
		{"AES-256", aes256GcmSivVectors},
	} {
		t.Run(vectors.name, func(t *testing.T) {
			for i, vector := range vectors.list {
				decode := func(s string) []byte {
					b, err := hex.DecodeString(s)
					if err != nil {
						t.Fatalf("vector %d: %v", i, err)
					}
					return b
				}
				cipher, err := aesgcmsiv.NewAesGcmSiv(decode(vector.key))
				if err != nil {
					t.Fatalf("vector %d: NewAesGcmSiv: %v", i, err)
				}
				got, err := cipher.Seal(decode(vector.nonce), decode(vector.plaintext), decode(vector.aad))
				if err != nil {
					cipher.FreeAesGcmSiv()
					t.Fatalf("vector %d: Seal: %v", i, err)
				}
				want := decode(vector.out)
				if !bytes.Equal(got, want) {
					cipher.FreeAesGcmSiv()
					t.Fatalf("vector %d: Seal mismatch\n got %x\nwant %x", i, got, want)
				}
				opened, err := cipher.Open(decode(vector.nonce), want, decode(vector.aad))
				cipher.FreeAesGcmSiv()
				if err != nil {
					t.Fatalf("vector %d: Open: %v", i, err)
				}
				if !bytes.Equal(opened, decode(vector.plaintext)) {
					t.Fatalf("vector %d: Open mismatch", i)
				}
			}
		})
	}
}
