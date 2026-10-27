// Package aesgcmsiv is AES-GCM-SIV for Golang
package aesgcmsiv

/*
#cgo CFLAGS: -I${SRCDIR}/../lib/include -I${SRCDIR}/../lib/src -I${SRCDIR}/../lib/src/arm64 -I${SRCDIR}/../lib/src/generic -I${SRCDIR}/../lib/src/x86_64
#cgo amd64 CFLAGS: -DUSE_INTRINSICS
#cgo arm64 CFLAGS: -DUSE_INTRINSICS -march=armv8-a+crypto

#include <stdlib.h>
#include "aes_gcmsiv.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

type Aesgcmsiv struct {
	aes *C.struct_aes_gcmsiv_ctx
}

/*
NewAesGcmSiv : Create an AES-GCM-SIV cipher for a specified key.

	Parameters:
		key - the AES key, whose length can be 128 or 256 bits (16 or 32 bytes respectively). AES-GCM-SIV does not support AES with a key of 192 bits.
	Returns:
		ctx - It will be null if initialization fails.
		error - It will be null if initialization succeeded.
*/
func NewAesGcmSiv(key []byte) (*Aesgcmsiv, error) {
	var err error = nil
	var keyPtr *C.uint8_t = nil
	if 0 < len(key) {
		keyPtr = (*C.uint8_t)(unsafe.Pointer(&key[0]))
	}

	ctx := new(Aesgcmsiv)
	ctx.aes = nil

	// We don't have to check nil for C.malloc since C.malloc is guaranteed never to return nil.
	// If C's malloc indicates out of memory, the helper function crashes the program, like when Go itself runs out of memory.
	// See https://pkg.go.dev/cmd/cgo#hdr-Go_references_to_C
	ctx.aes = (*C.struct_aes_gcmsiv_ctx)(C.malloc(C.aes_gcmsiv_context_size()))

	C.aes_gcmsiv_init(ctx.aes)
	res := C.aes_gcmsiv_set_key(ctx.aes, keyPtr, C.size_t(len(key)))
	if C.AES_GCMSIV_SUCCESS != res {
		ctx.FreeAesGcmSiv()
		err = ctx.getErrorByStatus(res)
		return nil, err
	}

	return ctx, nil
}

// FreeAesGcmSiv : Release objects you should call this function after calling Seal/Open. See examples in GoDoc or aesgcmsiv_test.go.
func (ctx *Aesgcmsiv) FreeAesGcmSiv() {
	if ctx == nil || ctx.aes == nil {
		return
	}
	C.aes_gcmsiv_free(ctx.aes)
	C.free(unsafe.Pointer(ctx.aes))
	ctx.aes = nil
}

// NonceSize : Byte size for AES-GCM-SIV nonce
func (ctx *Aesgcmsiv) NonceSize() int {
	return C.AES_GCMSIV_NONCE_SIZE
}

// Overhead : Byte size for Tag
func (ctx *Aesgcmsiv) Overhead() int {
	return C.AES_GCMSIV_TAG_SIZE
}

/*
Seal : Encrypt plaintext ( for confidentiality ), and do data-authentication ( for integrity ) this plaintext and AAD ( Additional Authenticated Data ).

	Parameters:
		nonce - the random (but not secret) nonce to use for this encryption. It must be 96-bit long (12 bytes).
		plaintext - It provides confidentiality and integrity for plaintext. It can be null or empty if there is no data to encrypt, but only AAD to authenticate. Maximum size is 2^36 bytes.
		aad - ( option ) It provides only integrity for AAD, and doesn't provide confidentiality for AAD. Maximum size is 2^36 bytes.
	Returns:
		ciphertext+tag - It will be null if encryption fails. The last 16 bytes are the tag, which is used to check the integrity of the ciphertext and aad.
		error - It will be null if encryption succeeds
*/
func (ctx *Aesgcmsiv) Seal(nonce, plaintext, aad []byte) ([]byte, error) {

	var err error = nil

	_aad := (*C.uint8_t)(nil)
	_plain := (*C.uint8_t)(nil)
	_nonce := (*C.uint8_t)(nil)
	var cipher []byte
	var bufferSize C.size_t

	if ctx == nil || ctx.aes == nil {
		err = errors.New("aesgcmsiv: you cannot call Seal/Open after FreeAesGcmSiv(). Please create new instance by NewAesGcmSiv")
		return nil, err
	}

	res := C.aes_gcmsiv_encrypt_size(C.size_t(len(plaintext)),
		C.size_t(len(aad)),
		&bufferSize)
	if C.AES_GCMSIV_SUCCESS != res {
		err = ctx.getErrorByStatus(res)
		return nil, err
	}

	cipher = make([]byte, bufferSize)

	if len(aad) > 0 {
		_aad = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
	}

	if len(plaintext) > 0 {
		_plain = (*C.uint8_t)(unsafe.Pointer(&plaintext[0]))
	}

	if len(nonce) > 0 {
		_nonce = (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
	}
	res = C.aes_gcmsiv_encrypt_with_tag(ctx.aes,
		(*C.uint8_t)(_nonce), C.size_t(len(nonce)),
		(*C.uint8_t)(_plain), C.size_t(len(plaintext)),
		(*C.uint8_t)(_aad), C.size_t(len(aad)),
		(*C.uint8_t)(unsafe.Pointer(&cipher[0])), bufferSize, &bufferSize)

	if C.AES_GCMSIV_SUCCESS != res {
		err = ctx.getErrorByStatus(res)
		return nil, err
	}

	return cipher, err
}

/*
Open : Decrypt ciphertext, and do data-authentication this ciphertext and AAD ( Additional Authenticated Data ).

	Parameters:
		nonce - the random ( but not secret ) nonce used during the encryption. It must be 96-bit long (12 bytes).
		ciphertext+tag - the data to be decrypted. It must have a minimum size of 16-bytes, which is the size of the authentication tag.
		aad - ( option ) It provides only integrity for AAD, and doesn't provide confidentiality for AAD.
	Returns:
		plaintext - It will be null if decryption fails.
		error - It will be null if decryption succeeds
*/
func (ctx *Aesgcmsiv) Open(nonce, ciphertext, aad []byte) ([]byte, error) {

	var err error = nil

	if ctx == nil || ctx.aes == nil {
		err = errors.New("aesgcmsiv: you cannot call Seal/Open after FreeAesGcmSiv(). Please create new instance by NewAesGcmSiv")
		return nil, err
	}

	_aad := (*C.uint8_t)(nil)
	_plain := (*C.uint8_t)(nil)
	_nonce := (*C.uint8_t)(nil)
	var plaintext []byte

	if len(aad) > 0 {
		_aad = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
	}

	var bufferSize C.size_t

	res := C.aes_gcmsiv_decrypt_size(C.size_t(len(ciphertext)),
		C.size_t(len(aad)),
		&bufferSize)
	if C.AES_GCMSIV_SUCCESS != res {
		err = ctx.getErrorByStatus(res)
		return nil, err
	}
	plaintext = make([]byte, bufferSize)
	if len(plaintext) > 0 {
		_plain = (*C.uint8_t)(unsafe.Pointer(&plaintext[0]))
	}

	if len(nonce) > 0 {
		_nonce = (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
	}

	res = C.aes_gcmsiv_decrypt_and_check(ctx.aes,
		(*C.uint8_t)(_nonce), C.size_t(len(nonce)),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), C.size_t(len(ciphertext)),
		(*C.uint8_t)(_aad), C.size_t(len(aad)),
		(*C.uint8_t)(_plain), bufferSize, &bufferSize)
	if C.AES_GCMSIV_SUCCESS != res {
		err = ctx.getErrorByStatus(res)
		return nil, err
	}

	return plaintext, err

}

func (ctx *Aesgcmsiv) getErrorByStatus(status C.aes_gcmsiv_status_t) error {
	ret := C.aes_gcmsiv_get_status_code_msg(status)
	return errors.New(C.GoString(ret))
}
