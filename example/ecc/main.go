package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"

	tinkjwt "github.com/salrashid123/golang-jwt-tink"
)

var (
	pubK  = flag.String("pubK", "pub.json", "Tink PublicKey")
	privK = flag.String("privK", "priv.json", "Tink PrivateKey")
	keyID = flag.Uint("keyID", 0, "Tink PrivateKey")
)

func main() {

	flag.Parse()
	ctx := context.Background()

	log.Printf("======= Init  ========")

	privKBytes, err := os.ReadFile(*privK)
	if err != nil {
		log.Fatalf("Error error reading private key %v", err)
	}

	privReader := keyset.NewJSONReader(bytes.NewReader(privKBytes))
	privateKeyHandle, err := insecurecleartextkeyset.Read(privReader)
	if err != nil {
		log.Fatal(err)
	}

	prMgr := keyset.NewManagerFromHandle(privateKeyHandle)
	prMgr.SetPrimary(uint32(*keyID))

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	tinkjwt.SigningMethodTINKES256.Override()
	token := jwt.NewWithClaims(tinkjwt.SigningMethodTINKES256, claims)

	config := &tinkjwt.TINKConfig{
		Key: privateKeyHandle,
	}

	keyctx, err := tinkjwt.NewTINKContext(ctx, config)
	if err != nil {
		log.Fatalf("Unable to initialize tpmJWT: %v", err)
	}

	c, ok := tinkjwt.TINKFromContext(keyctx)
	if !ok {
		log.Fatalf("Unable to initialize tinkJWT: %v", err)
	}
	c.GetPublicKey()

	pubkey_bytes, err := x509.MarshalPKIXPublicKey(c.GetPublicKey())
	if err != nil {
		log.Fatalf("JSON parse error: %v ", err)
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)
	log.Printf("ECC PublicKey: \n%s\n", string(pubkey_pem))

	// optionally set a keyID
	//token.Header["kid"] = config.GetKeyID()

	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		log.Fatalf("Error signing %v", err)
	}
	fmt.Printf("TOKEN: %s\n", tokenString)

	// verify with TINK based publicKey
	keyFunc, err := tinkjwt.TINKVerfiyKeyfunc(ctx, config)
	if err != nil {
		log.Fatalf("could not get keyFunc: %v", err)
	}

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if vtoken.Valid {
		log.Println("     verified with TINK PublicKey")
	}

	// verify with provided RSAPublic key
	pubKeyr := config.GetPublicKey()

	v, err := jwt.Parse(vtoken.Raw, func(token *jwt.Token) (interface{}, error) {
		return pubKeyr, nil
	})
	if err != nil {
		log.Fatalf("Error parsing token %v", err)
	}
	if v.Valid {
		log.Println("     verified with exported PubicKey")
	}

	//  now verify with just the public key

	pubKBytes, err := os.ReadFile(*pubK)
	if err != nil {
		log.Fatalf("Error error reading public key %v", err)
	}
	publicKeyReader := keyset.NewJSONReader(bytes.NewReader(pubKBytes))
	publicKeyHandle, err := insecurecleartextkeyset.Read(publicKeyReader)
	if err != nil {
		log.Fatal(err)
	}

	puMgr := keyset.NewManagerFromHandle(privateKeyHandle)
	puMgr.SetPrimary(uint32(*keyID))

	configP := &tinkjwt.TINKConfig{
		Key: publicKeyHandle,
	}

	keyctxP, err := tinkjwt.NewTINKContext(ctx, configP)
	if err != nil {
		log.Fatalf("Unable to initialize tinkJWT: %v", err)
	}
	// verify with TINK based publicKey
	keyFuncP, err := tinkjwt.TINKVerfiyKeyfunc(keyctxP, configP)
	if err != nil {
		log.Fatalf("could not get keyFunc: %v", err)
	}

	vtokenP, err := jwt.Parse(tokenString, keyFuncP)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if vtokenP.Valid {
		log.Println("     verified with TINK PublicKey")
	}
}
