# AES-GCM-SIV Go library

This package wraps the native C implementation in [`../lib`](../lib) using cgo. A C compiler is required.

```go
cipher, err := aesgcmsiv.NewAesGcmSiv(key)
if err != nil {
    return err
}
defer cipher.FreeAesGcmSiv()

ciphertext, err := cipher.Seal(nonce, plaintext, additionalData)
plaintext, err = cipher.Open(nonce, ciphertext, additionalData)
```

Run the RFC 8452 test vectors with `go test` from this directory.
