package common

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"reflect"
	"testing"
)

func TestLoadAndStoreFile(t *testing.T) {

	originalKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	StoreRSAPrivateKeyPEM(originalKey, "testdata/testkey.pem")

	loadedKey, _ := LoadRSAPrivateKeyPEM("testdata/testkey.pem")

	if !originalKey.Equal(loadedKey) {
		t.Errorf("store and load failed")
	}
}

func TestStringPEMRSA(t *testing.T) {

	originalKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	pubkey := originalKey.PublicKey

	stringKey, _ := PublicKeyToStringPEM(&pubkey)

	fmt.Println(stringKey)

	parsedKey, _ := PublicKeyFromStringPEM(stringKey)

	if !pubkey.Equal(parsedKey) {
		t.Errorf("string convert and parse failed (RSA)")
	}

}
func TestStringPEMEd25519(t *testing.T) {

	pubkey, _, _ := ed25519.GenerateKey(rand.Reader)

	stringKey, _ := PublicKeyToStringPEM(&pubkey)

	fmt.Println(stringKey)

	parsedKey, _ := PublicKeyFromStringPEM(stringKey)

	if !pubkey.Equal(parsedKey) {
		t.Errorf("string convert and parse failed (Ed25519)")
	}

}

func TestEncodeDecodePublicKeysEd25519(t *testing.T) {
	pubkey, _, _ := ed25519.GenerateKey(rand.Reader)

	keystring, alg, err := EncodePublicKey(&pubkey)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(keystring, alg)

	decodedPkey, err := DecodePublicKey(keystring, alg)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(reflect.TypeOf(decodedPkey))
	if !pubkey.Equal(decodedPkey) {
		t.Errorf("string convert and parse failed (Ed25519)")
	}

}

func TestEncodeDecodePublicKeysRSA(t *testing.T) {
	originalKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	pubkey := originalKey.PublicKey

	keystring, alg, err := EncodePublicKey(&pubkey)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(keystring, alg)

	decodedPkey, err := DecodePublicKey(keystring, alg)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(reflect.TypeOf(decodedPkey))
	if !pubkey.Equal(decodedPkey) {
		t.Errorf("string convert and parse failed (Ed25519)")
	}

}
