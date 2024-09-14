package pact

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type params struct {
	ciphertext     string
	plaintext      string
	nonce          string
	key            string
	associatedData string
	comPACT        bool
}

var testVectors = map[string]params{
	"PACT": {
		ciphertext:     "7c0df61c33f0c998dbe516797c7908dcdfd52f1f10ec0b5ae2e4de9942ced85eeec8b953385268b2f9fb8414d169f7f4b24a93c0b5d29afbe1b442dc4077e8f48f22ad0a409f977cac9fcaf05be1ba04040f8b04667362fff434a71b9f2d09a3e14283372d3c5946111486e8c1a155a28965779e37dccdc61be3fd3c8b66a3430ef8",
		plaintext:      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
		nonce:          "070000004041424344454647",
		key:            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
		associatedData: "50515253c0c1c2c3c4c5c6c7",
		comPACT:        false,
	},
	"comPACT": {
		ciphertext:     "7c0df61c33f0c998dbe516797c7908dcdfd52f1f10ec0b5ae2e4de9942ced85eeec8b953385268b2f9fb8414d169f7f4b24a93c0b5d29afbe1b442dc4077e8f48f22ad0a409f977cac9fcaf05be1ba04040f8b04667362fff434a71b9f2d09a3e14283372d3c5946111486e8c1a155a289651f568c271cd2eda7e8147066a8d3caef",
		plaintext:      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
		nonce:          "070000004041424344454647",
		key:            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
		associatedData: "50515253c0c1c2c3c4c5c6c7",
		comPACT:        true,
	},
}

func TestConstantsValid(t *testing.T) {
	if KeySize != 32 {
		t.Errorf("KeySize should be 32")
	}
	if NonceSize != 12 {
		t.Errorf("NonceSize should be 12")
	}
	if TagSize != 16 {
		t.Errorf("TagSize should be 16")
	}
}

func TestEncryptValid(t *testing.T) {
	for testName, testVector := range testVectors {
		t.Run(testName, func(t *testing.T) {
			expected, _ := hex.DecodeString(testVector.ciphertext)
			plaintext, _ := hex.DecodeString(testVector.plaintext)
			nonce, _ := hex.DecodeString(testVector.nonce)
			key, _ := hex.DecodeString(testVector.key)
			associatedData, _ := hex.DecodeString(testVector.associatedData)

			actual, err := Encrypt(plaintext, nonce, key, associatedData, testVector.comPACT)

			if !bytes.Equal(expected, actual) {
				t.Errorf("ciphertext doesn't match")
			}
			if err != nil {
				t.Errorf("err should be nil")
			}
		})
	}
}

func TestEncryptInvalid(t *testing.T) {
	parameters := []struct {
		plaintextSize      int
		nonceSize          int
		keySize            int
		associatedDataSize int
		comPACT            bool
	}{
		{0, NonceSize + 1, KeySize, 0, false},
		{0, NonceSize - 1, KeySize, 0, false},
		{0, NonceSize, KeySize + 1, 0, false},
		{0, NonceSize, KeySize - 1, 0, false},
	}

	for _, invalidParams := range parameters {
		t.Run("", func(t *testing.T) {
			plaintext := make([]byte, invalidParams.plaintextSize)
			nonce := make([]byte, invalidParams.nonceSize)
			key := make([]byte, invalidParams.keySize)
			associatedData := make([]byte, invalidParams.associatedDataSize)

			ciphertext, err := Encrypt(plaintext, nonce, key, associatedData, invalidParams.comPACT)

			if err == nil {
				t.Errorf("encrypt should fail")
			}
			if ciphertext != nil {
				t.Errorf("ciphertext should be nil")
			}
		})
	}
}

func TestDecryptValid(t *testing.T) {
	for testName, testVector := range testVectors {
		t.Run(testName, func(t *testing.T) {
			expected, _ := hex.DecodeString(testVector.plaintext)
			ciphertext, _ := hex.DecodeString(testVector.ciphertext)
			nonce, _ := hex.DecodeString(testVector.nonce)
			key, _ := hex.DecodeString(testVector.key)
			associatedData, _ := hex.DecodeString(testVector.associatedData)

			actual, err := Decrypt(ciphertext, nonce, key, associatedData, testVector.comPACT)

			if !bytes.Equal(expected, actual) {
				t.Errorf("plaintext doesn't match")
			}
			if err != nil {
				t.Errorf("err should be nil")
			}
		})
	}
}

func TestDecryptTampered(t *testing.T) {
	hexDecode := func(s string) []byte {
		decoded, _ := hex.DecodeString(s)
		return decoded
	}

	for _, testVector := range testVectors {
		t.Run("", func(t *testing.T) {
			parameters := [][]byte{
				hexDecode(testVector.ciphertext),
				hexDecode(testVector.nonce),
				hexDecode(testVector.key),
				hexDecode(testVector.associatedData),
			}

			for i := 0; i < len(parameters); i++ {
				if len(parameters[i]) == 0 {
					continue
				}

				parameters[i][0]++
				plaintext, err := Decrypt(parameters[0], parameters[1], parameters[2], parameters[3], testVector.comPACT)
				parameters[i][0]--

				if err == nil {
					t.Errorf("decrypt should fail")
				}
				if plaintext != nil {
					t.Errorf("plaintext should be nil")
				}
			}
		})
	}
}

func TestDecryptInvalid(t *testing.T) {
	parameters := []struct {
		ciphertextSize     int
		nonceSize          int
		keySize            int
		associatedDataSize int
		comPACT            bool
	}{
		{TagSize - 1, NonceSize, KeySize, 0, false},
		{TagSize, NonceSize + 1, KeySize, 0, false},
		{TagSize, NonceSize - 1, KeySize, 0, false},
		{TagSize, NonceSize, KeySize + 1, 0, false},
		{TagSize, NonceSize, KeySize - 1, 0, false},
	}

	for _, invalidParams := range parameters {
		t.Run("", func(t *testing.T) {
			ciphertext := make([]byte, invalidParams.ciphertextSize)
			nonce := make([]byte, invalidParams.nonceSize)
			key := make([]byte, invalidParams.keySize)
			associatedData := make([]byte, invalidParams.associatedDataSize)

			plaintext, err := Decrypt(ciphertext, nonce, key, associatedData, invalidParams.comPACT)

			if err == nil {
				t.Errorf("decrypt should fail")
			}
			if plaintext != nil {
				t.Errorf("plaintext should be nil")
			}
		})
	}
}
