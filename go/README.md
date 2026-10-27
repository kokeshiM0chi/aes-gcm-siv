# AES-GCM-SIV Go library

This package is a cgo wrapper around the C implementation in [`../lib`](../lib).
It provides the `NewAesGcmSiv`, `Seal`, `Open`, and `FreeAesGcmSiv` API.
The C sources are compiled with the Go package,
so a separate CMake build and C submodule are unnecessary.

## Requirements

- Go 1.20 or newer
- A C compiler and `CGO_ENABLED=1`

Until the first release that contains this package, install the current branch
with `go get github.com/line/aes-gcm-siv/go@master`. After that release, use
`go get github.com/line/aes-gcm-siv/go`.

## Usage

```go
package main

import (
	"crypto/rand"
	"log"

	aesgcmsiv "github.com/line/aes-gcm-siv/go"
)

func main() {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		log.Fatal(err)
	}

	cipher, err := aesgcmsiv.NewAesGcmSiv(key)
	if err != nil {
		log.Fatal(err)
	}
	defer cipher.FreeAesGcmSiv()

	sealed, err := cipher.Seal(nonce, []byte("message"), nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := cipher.Open(nonce, sealed, nil); err != nil {
		log.Fatal(err)
	}
}
```

Keys must be 16 or 32 bytes and nonces must be 12 bytes. `Seal` appends a
16-byte authentication tag, and `Open` verifies it. Call `FreeAesGcmSiv` after
the last operation; do not use a cipher after freeing it. Calls to `Seal` and
`Open` may share an initialized cipher, but `FreeAesGcmSiv` must not run
concurrently with them.

On x86-64 and ARM64, the package enables the C implementation's CPU intrinsics
and selects hardware instructions at runtime when available. Other CPUs use
the generic C implementation.

Run the RFC 8452 known-answer tests with `go test ./go` from the repository root.
