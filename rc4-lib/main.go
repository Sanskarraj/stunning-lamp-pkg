package main

import (
	"encoding/hex"
	"fmt"
)

// rc4 performs the RC4 algorithm on the given data using the provided key.
func rc4(key []byte, data []byte) []byte {
	s := make([]byte, 256)
	for i := range s {
		s[i] = byte(i)
	}

	// Key-scheduling algorithm (KSA)
	var j int
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) % 256
		s[i], s[j] = s[j], s[i]
	}

	// Pseudo-random generation algorithm (PRGA)
	var i int
	j = 0
	result := make([]byte, len(data))
	for n, b := range data {
		i = (i + 1) % 256
		j = (j + int(s[i])) % 256
		s[i], s[j] = s[j], s[i]
		k := s[(int(s[i])+int(s[j]))%256]
		result[n] = b ^ k
	}

	return result
}

// RC4Encrypt encrypts the input data using the provided key and returns the result as a hex-encoded string.
func RC4Encrypt(key string, data string) string {
	keyBytes := []byte(key)
	dataBytes := []byte(data)
	encryptedData := rc4(keyBytes, dataBytes)
	return hex.EncodeToString(encryptedData)
}

// RC4Decrypt decrypts the hex-encoded input data using the provided key and returns the result as a string.
func RC4Decrypt(key string, data string) (string, error) {
	keyBytes := []byte(key)
	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}
	decryptedData := rc4(keyBytes, dataBytes)
	return string(decryptedData), nil
}

func main() {
	// Example usage
	key := "my-secret-key"
	data := "Hello, World!"
	q:="2b30423125ac1ac1172c6fc403"

	encrypted := RC4Encrypt(key, data)
	if encrypted == q {
		fmt.Println("Match")
	} else {
		fmt.Println("Not Matched")
	}
	fmt.Println("Encrypted:", encrypted)

	decrypted, err := RC4Decrypt(key, encrypted)
	if err != nil {
		fmt.Println("Error during decryption:", err)
	} else {
		fmt.Println("Decrypted:", decrypted)
	}
}
