package tinkjwt

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

var ()

const (
	RSA_PUBLIC_KEYSET  = "example/keyset/rsa_2_public_keyset.json"
	RSA_PRIVATE_KEYSET = "example/keyset/rsa_2_privatekey_keyset.json"

	RSA_PSS_PRIVATE_KEYSET = "example/keyset/rsa_pss_privatekey_keyset.json"

	ECC_PUBLIC_KEYSET  = "example/keyset/ecc_1_public_keyset.json"
	ECC_PRIVATE_KEYSET = "example/keyset/ecc_1_privatekey_keyset.json"
)

func TestRSA(t *testing.T) {

	keysetBytes, err := os.ReadFile(RSA_PRIVATE_KEYSET)
	require.NoError(t, err)

	privReader := keyset.NewJSONReader(bytes.NewReader(keysetBytes))
	privateKeyHandle, err := insecurecleartextkeyset.Read(privReader)
	require.NoError(t, err)

	SigningMethodTINKRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTINKRS256, claims)

	config := &TINKConfig{
		Key:   privateKeyHandle,
		KeyID: "123569881",
	}
	keyctx, err := NewTINKContext(context.Background(), config)
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := TINKVerfiyKeyfunc(context.Background(), config)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}

func TestRSAPSS(t *testing.T) {

	keysetBytes, err := os.ReadFile(RSA_PSS_PRIVATE_KEYSET)
	require.NoError(t, err)

	privReader := keyset.NewJSONReader(bytes.NewReader(keysetBytes))
	privateKeyHandle, err := insecurecleartextkeyset.Read(privReader)
	require.NoError(t, err)

	SigningMethodTINKRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTINKPS256, claims)

	config := &TINKConfig{
		Key: privateKeyHandle,
		//KeyID: "634725369",
	}
	keyctx, err := NewTINKContext(context.Background(), config)
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := TINKVerfiyKeyfunc(context.Background(), config)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}

func TestEC(t *testing.T) {

	keysetBytes, err := os.ReadFile(ECC_PRIVATE_KEYSET)
	require.NoError(t, err)

	privReader := keyset.NewJSONReader(bytes.NewReader(keysetBytes))
	privateKeyHandle, err := insecurecleartextkeyset.Read(privReader)
	require.NoError(t, err)

	SigningMethodTINKRS256.Override()

	issuer := "test"
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    issuer,
	}
	token := jwt.NewWithClaims(SigningMethodTINKES256, claims)

	config := &TINKConfig{
		Key:   privateKeyHandle,
		KeyID: "1500225574",
	}
	keyctx, err := NewTINKContext(context.Background(), config)
	require.NoError(t, err)

	tokenString, err := token.SignedString(keyctx)
	require.NoError(t, err)

	// verify with TPM based publicKey
	keyFunc, err := TINKVerfiyKeyfunc(context.Background(), config)
	require.NoError(t, err)

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	require.NoError(t, err)

	require.True(t, vtoken.Valid)
}
