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
	"strconv"
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
	mode  = flag.String("mode", "rsa", "test rsa or rsapss")
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

	// list all the keyID in this keyset

	log.Printf("private keyset default primary keyID: %d\n", privateKeyHandle.KeysetInfo().PrimaryKeyId)
	for _, k := range privateKeyHandle.KeysetInfo().KeyInfo {
		log.Printf("private keyset contains keyID: %d with status %s\n", k.KeyId, k.Status)
	}
	// note, we are setting the provided keyid to the primarykey
	//  do not persist this keyset or reuse it since the keyid has changed
	prMgr := keyset.NewManagerFromHandle(privateKeyHandle)
	if *keyID != 0 {
		err = prMgr.SetPrimary(uint32(*keyID))
		if err != nil {
			log.Fatal(err)
		}
	}

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	var token *jwt.Token

	if *mode == "rsapss" {
		tinkjwt.SigningMethodTINKPS256.Override()
		token = jwt.NewWithClaims(tinkjwt.SigningMethodTINKPS256, claims)
	} else {
		tinkjwt.SigningMethodTINKRS256.Override()
		token = jwt.NewWithClaims(tinkjwt.SigningMethodTINKRS256, claims)

	}

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

	pubkey_bytes, err := x509.MarshalPKIXPublicKey(c.GetPublicKey())
	if err != nil {
		log.Fatalf("JSON parse error: %v ", err)
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)
	log.Printf("RSA PublicKey: \n%s\n", string(pubkey_pem))

	// set a keyID
	token.Header["kid"] = config.GetKeyID()

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

	// if you just want to parse the token but not verify (eg to extract the keyid), supply nil as keyFunc
	vtoken, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		log.Fatalf("Error verifying token %v", err)
	}
	if vtoken.Valid {
		log.Println("     verified with TINK PublicKey")
	}

	kidFromToken := vtoken.Header["kid"]
	log.Printf("     using KeyID: %s\n", kidFromToken)
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

	log.Printf("public keyset default primary keyID: %d\n", publicKeyHandle.KeysetInfo().PrimaryKeyId)
	for _, k := range publicKeyHandle.KeysetInfo().KeyInfo {
		log.Printf("public keyset contains keyID: %d with status %s\n", k.KeyId, k.Status)
	}

	ukid, err := strconv.Atoi(kidFromToken.(string))
	if err != nil {
		log.Fatal(err)
	}

	puMgr := keyset.NewManagerFromHandle(publicKeyHandle)
	if *keyID != 0 {
		err = puMgr.SetPrimary(uint32(ukid))
		if err != nil {
			log.Fatal(err)
		}
	}
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
