package pact

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

const (
	KeySize   = 32
	NonceSize = 12
	TagSize   = 16
)

func Encrypt(plaintext []byte, nonce []byte, key []byte, associatedData []byte, comPACT bool) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errors.New("nonce length must be equal to NonceSize")
	}
	if len(key) != KeySize {
		return nil, errors.New("key length must be equal to KeySize")
	}

	aes256, _ := aes.NewCipher(key)
	aesGcm, _ := cipher.NewGCM(aes256)
	var ciphertext []byte
	if comPACT {
		ciphertext = aesGcm.Seal(nil, nonce, plaintext, nil)
	} else {
		ciphertext = aesGcm.Seal(nil, nonce, plaintext, associatedData)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write(associatedData)
	subkey := mac.Sum(nil)

	aes256, _ = aes.NewCipher(subkey)
	tag := ciphertext[len(ciphertext)-TagSize:]
	aes256.Encrypt(tag, tag)
	return ciphertext, nil
}

func Decrypt(ciphertext []byte, nonce []byte, key []byte, associatedData []byte, comPACT bool) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, errors.New("ciphertext length must be greater than or equal to TagSize")
	}
	if len(nonce) != NonceSize {
		return nil, errors.New("nonce length must be equal to NonceSize")
	}
	if len(key) != KeySize {
		return nil, errors.New("key length must be equal to KeySize")
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write(associatedData)
	subkey := mac.Sum(nil)

	aes256, _ := aes.NewCipher(subkey)
	originalCiphertext := make([]byte, len(ciphertext))
	copy(originalCiphertext, ciphertext)
	aes256.Decrypt(originalCiphertext[len(ciphertext)-TagSize:], ciphertext[len(ciphertext)-TagSize:])

	aes256, _ = aes.NewCipher(key)
	aesGcm, _ := cipher.NewGCM(aes256)
	if comPACT {
		return aesGcm.Open(nil, nonce, originalCiphertext, nil)
	} else {
		return aesGcm.Open(nil, nonce, originalCiphertext, associatedData)
	}
}
