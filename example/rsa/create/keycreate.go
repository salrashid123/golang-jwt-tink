package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	rsppb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/signature"
	"google.golang.org/protobuf/proto"
)

const ()

var (
	pubK  = flag.String("pubK", "pub.json", "Tink PublicKey")
	privK = flag.String("privK", "priv.json", "Tink PrivateKey")
)

func bytesToBigInt(v []byte) *big.Int {
	return new(big.Int).SetBytes(v)
}

func main() {

	flag.Parse()
	// create keyset
	privateKeysetHandle, err := keyset.NewHandle(signature.RSA_SSA_PKCS1_3072_SHA256_F4_RAW_Key_Template())
	if err != nil {
		log.Fatal(err)
	}

	prbuf := new(bytes.Buffer)
	prw := keyset.NewJSONWriter(prbuf)
	err = insecurecleartextkeyset.Write(privateKeysetHandle, prw)
	if err != nil {
		log.Fatal(err)
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, prbuf.Bytes(), "", "\t")
	if err != nil {
		log.Fatalf("JSON parse error: %v ", err)
	}
	privateJSONKeyset := prettyJSON.String()
	log.Printf("Tink Keyset: %s\n", privateJSONKeyset)

	// write it to private key to file
	err = os.WriteFile(*privK, prettyJSON.Bytes(), 0644)
	if err != nil {
		log.Fatalf("JSON parse error: %v ", err)
	}

	log.Printf("Created PrimaryKeyId %d\n", privateKeysetHandle.KeysetInfo().PrimaryKeyId)

	// print the keytype
	for _, k := range privateKeysetHandle.KeysetInfo().GetKeyInfo() {
		log.Printf("  Found TypeUrl: %s\n", k.TypeUrl)
	}

	// get the public key
	publicKeysetHandle, err := privateKeysetHandle.Public()
	if err != nil {
		log.Fatalf("JSON parse error: %v ", err)
	}

	// print it out
	pubuf := new(bytes.Buffer)
	pubw := keyset.NewJSONWriter(pubuf)
	err = insecurecleartextkeyset.Write(publicKeysetHandle, pubw)
	if err != nil {
		log.Fatal(err)
	}
	var pubPrettyJSON bytes.Buffer
	err = json.Indent(&pubPrettyJSON, pubuf.Bytes(), "", "\t")
	if err != nil {
		log.Fatalf("JSON parse error: %v ", err)
	}
	publicJSONKeyset := pubPrettyJSON.String()
	log.Printf("Tink Keyset: %s\n", publicJSONKeyset)

	// write to a file
	err = os.WriteFile(*pubK, pubPrettyJSON.Bytes(), 0644)
	if err != nil {
		log.Fatalf("JSON parse error: %v ", err)
	}
	/// **********

	signer, err := signature.NewSigner(privateKeysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	// Use the primitive to sign a message. In this case, the primary key of the
	// keyset will be used (which is also the only key in this example).
	data := []byte("data")
	sig, err := signer.Sign(data)
	if err != nil {
		log.Fatal(err)
	}

	for _, k := range publicKeysetHandle.KeysetInfo().GetKeyInfo() {
		log.Printf("  Found TypeUrl: %s\n", k.TypeUrl)
	}

	// Retrieve the Verifier primitive from publicKeysetHandle.
	verifier, err := signature.NewVerifier(publicKeysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	if err = verifier.Verify(sig, data); err != nil {
		log.Fatal(err)
	}
	log.Printf("signature verified using tink\n")
	// Output: sig is valid

	//
	// now extract out the public key as rsa

	log.Println(publicKeysetHandle.KeysetInfo().GetKeyInfo()[0].TypeUrl)

	bbw := new(bytes.Buffer)
	bw := keyset.NewBinaryWriter(bbw)
	err = publicKeysetHandle.WriteWithNoSecrets(bw)
	if err != nil {
		log.Fatalf("Could not write encrypted keyhandle %v", err)
	}

	tpb := &tinkpb.Keyset{}

	err = proto.Unmarshal(bbw.Bytes(), tpb)
	if err != nil {
		log.Fatal(err)
	}

	for _, kk := range tpb.Key {
		kserialized := kk.KeyData.Value

		key := &rsppb.RsaSsaPkcs1PublicKey{}
		if err := proto.Unmarshal(kserialized, key); err != nil {
			log.Fatal(err)
		}

		pubKey := &rsa.PublicKey{
			E: int(bytesToBigInt(key.GetE()).Int64()),
			N: bytesToBigInt(key.GetN()),
		}

		pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			log.Fatalf("JSON parse error: %v ", err)
		}
		pubkey_pem := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: pubkey_bytes,
			},
		)
		log.Printf("pubkey: \n%s\n", string(pubkey_pem))
		if key.Params.HashType == commonpb.HashType_SHA256 {
			digest := sha256.Sum256(data)
			verifyErr := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sig)

			if verifyErr != nil {
				log.Printf("Verification failed: %s", verifyErr)
				return
			}
			log.Println("signature verified using rsa.PublicKey")
		}

	}

}
