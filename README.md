# golang-jwt for Tink Keys

 [go-jwt](https://github.com/golang-jwt/jwt#extensions) extension for use with [Tink Cryptographic Library](https://developers.google.com/tink).

You can use this library to sign and verify a JWT using the standard `go-jwt` library semantics while the private and public keys are Tink Keysets

Note: Tink already has support for JWT signature and verification using its built-in [JWT Token](https://developers.google.com/tink/jwt) but this library allows you to easily use the more common JWT library in golang.

>> this repo is not supported by google

### Supported Key Types

The following types are supported

* `RS256`
* `ES256`

### Supported TINK Key Types:

Currently only the PrimaryK KeyID is used for signing and verification.

The Tink Key you use for signing should use the TINK or RAW prefix mode (`"outputPrefixType": "RAW"`, `"outputPrefixType": "TINK"`) as shown in the example.

The example in this repo uses the following templates:

* `signature.RSA_SSA_PKCS1_3072_SHA256_F4_RAW_Key_Template()`
* `signature.ECDSAP256KeyWithoutPrefixTemplate()`

but you can also use

  * `signature.RSA_SSA_PKCS1_3072_SHA256_F4_Key_Template()`
  * `signature.ECDSAP256KeyTemplate()`

for EC keys, only DER output format  (`EcdsaSignatureEncoding_DER`) is supported though a TODO is to also support `signature.ECDSAP256RawKeyTemplate()` 

Additional JWT signing library:

* [golang-jwt for Trusted Platform Module (TPM)](https://github.com/salrashid123/golang-jwt-tpm)
* [golang-jwt for PKCS11](https://github.com/salrashid123/golang-jwt-pkcs11)

---

### Usage

To  use, just initialize the library and provide it with a Tink KeyHandle:

For signing with RSA keys:

```golang
import (
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"

	tinkjwt "github.com/salrashid123/golang-jwt-tink"
)

// read a keyset (i'm using raw, insecure keyset but you can use any)
// the key here is type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey
privReader := keyset.NewJSONReader(bytes.NewReader(privKBytes))
privateKeyHandle, err := insecurecleartextkeyset.Read(privReader)

// create the claims you want to sign
claims := &jwt.RegisteredClaims{
	ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
	Issuer:    "test",
}

// initialize the signer
tinkjwt.SigningMethodTINKRS256.Override()

token := jwt.NewWithClaims(tinkjwt.SigningMethodTINKRS256, claims)

config := &tinkjwt.TINKConfig{
	Key: privateKeyHandle,
}

// sign
tokenString, err := token.SignedString(keyctx)
fmt.Printf("TOKEN: %s\n", tokenString)
```

To verify, you can just use the Public Key

```golang
// read in the public key
// "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey"
publicKeyReader := keyset.NewJSONReader(bytes.NewReader(pubKBytes))
publicKeyHandle, err := insecurecleartextkeyset.Read(publicKeyReader)

configP := &tinkjwt.TINKConfig{
	Key: publicKeyHandle,
}

keyctxP, err := tinkjwt.NewTINKContext(ctx, configP)

// verify with TINK based publicKey
keyFuncP, err := tinkjwt.TINKVerfiyKeyfunc(keyctxP, configP)

vtokenP, err := jwt.Parse(tokenString, keyFuncP)
if vtokenP.Valid {
	log.Println("     verified with TINK PublicKey")
}
```

See the [example/](example/) folder for end-to-end examples


---


#### RSA

Create a key

```log
$ go run rsa/create/main.go

2024/04/16 23:45:24 Tink Keyset: {
	"primaryKeyId": 2092034615,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
				"value": "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",
				"keyMaterialType": "ASYMMETRIC_PRIVATE"
			},
			"status": "ENABLED",
			"keyId": 2092034615,
			"outputPrefixType": "RAW"
		}
	]
}
2024/04/16 23:45:24 Created PrimaryKeyId 2092034615
2024/04/16 23:45:24   Found TypeUrl: type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey
2024/04/16 23:45:24 Tink Keyset: {
	"primaryKeyId": 2092034615,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey",
				"value": "EgIIAxqAA7zqLYtMcWpAgVlCWmB9yAD775u8EKiLdn8mup7ByZsPnxoSb4w3Y98Tv7c+rNIciNZ6qJrbaMhDGTKC/nL8XxAYgtnpgsCCF958sVi3mG+DrO5zhppTpg2V8E7IHbowBA4RAyyUuiCf1cMF5Q6eT2cWiTW5LI2yyau7hlUPeaTxjcgt0YKlApHyPRBFIBYQVPXAqSpea0bTg1GZr5BUp7Y5SP35AjuLuvTdHzOKbdkpzIagRCfAu6yXY/lLtI7kYJxxsRleNzYfjVDmeexZbTsqELHekODlrX4DOhLMYecXaW+SnRz5EgXceB7FRqHckv6z3SX92Fmf/kM749fGYAsn+9Soi08zF49+b4JCsovhbFL0k6VwGI1809aAsJuFmZnEmyorSe99O+HHRDnmg0GK+LB/xMA1MzYW4OcId30zfg9xAclS3SwITLPvSOoESax+Dn6G6hK52faItNrO26fYrkY2hpv1gvTpClDjSPxVKAD3/FYzkPUTYYL28WVmSyIDAQAB",
				"keyMaterialType": "ASYMMETRIC_PUBLIC"
			},
			"status": "ENABLED",
			"keyId": 2092034615,
			"outputPrefixType": "RAW"
		}
	]
}
2024/04/16 23:45:24   Found TypeUrl: type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey
2024/04/16 23:45:24 signature verified using tink
2024/04/16 23:45:24 type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey
2024/04/16 23:45:24 pubkey: 
-----BEGIN RSA PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAvOoti0xxakCBWUJaYH3I
APvvm7wQqIt2fya6nsHJmw+fGhJvjDdj3xO/tz6s0hyI1nqomttoyEMZMoL+cvxf
EBiC2emCwIIX3nyxWLeYb4Os7nOGmlOmDZXwTsgdujAEDhEDLJS6IJ/VwwXlDp5P
ZxaJNbksjbLJq7uGVQ95pPGNyC3RgqUCkfI9EEUgFhBU9cCpKl5rRtODUZmvkFSn
tjlI/fkCO4u69N0fM4pt2SnMhqBEJ8C7rJdj+Uu0juRgnHGxGV43Nh+NUOZ57Flt
OyoQsd6Q4OWtfgM6Esxh5xdpb5KdHPkSBdx4HsVGodyS/rPdJf3YWZ/+Qzvj18Zg
Cyf71KiLTzMXj35vgkKyi+FsUvSTpXAYjXzT1oCwm4WZmcSbKitJ73074cdEOeaD
QYr4sH/EwDUzNhbg5wh3fTN+D3EByVLdLAhMs+9I6gRJrH4OfobqErnZ9oi02s7b
p9iuRjaGm/WC9OkKUONI/FUoAPf8VjOQ9RNhgvbxZWZLAgMBAAE=
-----END RSA PUBLIC KEY-----

2024/04/16 23:45:24 signature verified using rsa.PublicKey
```


Sign

```log
$ go run rsa/sign/main.go

2024/04/16 23:45:53 ======= Init  ========
2024/04/16 23:45:53 RSA PublicKey: 
-----BEGIN RSA PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAvOoti0xxakCBWUJaYH3I
APvvm7wQqIt2fya6nsHJmw+fGhJvjDdj3xO/tz6s0hyI1nqomttoyEMZMoL+cvxf
EBiC2emCwIIX3nyxWLeYb4Os7nOGmlOmDZXwTsgdujAEDhEDLJS6IJ/VwwXlDp5P
ZxaJNbksjbLJq7uGVQ95pPGNyC3RgqUCkfI9EEUgFhBU9cCpKl5rRtODUZmvkFSn
tjlI/fkCO4u69N0fM4pt2SnMhqBEJ8C7rJdj+Uu0juRgnHGxGV43Nh+NUOZ57Flt
OyoQsd6Q4OWtfgM6Esxh5xdpb5KdHPkSBdx4HsVGodyS/rPdJf3YWZ/+Qzvj18Zg
Cyf71KiLTzMXj35vgkKyi+FsUvSTpXAYjXzT1oCwm4WZmcSbKitJ73074cdEOeaD
QYr4sH/EwDUzNhbg5wh3fTN+D3EByVLdLAhMs+9I6gRJrH4OfobqErnZ9oi02s7b
p9iuRjaGm/WC9OkKUONI/FUoAPf8VjOQ9RNhgvbxZWZLAgMBAAE=
-----END RSA PUBLIC KEY-----

TOKEN: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzEzMzI1NjEzfQ.f2EpojM28ufzANIyTIMyaZZmkIlrsayuML18vZetRTY9WZ6txOKGb6zmDLPJY2rSU2xmgxnZH3PHPtLakSa0egSebEgLdlxA9E2YMlgPwHyCat29Ppg5EwBUHiorniS3TH_zvvaCl4omcd-9RANGZl2M3p2LVCbpKFEsaZ4Gyz6FPwUDbrpX1gSzHhZuLOaVQ9QcciDq3HoWwBIxI7qtS1dxw8Jk7NIDaV6tBHgJsNJXJ9l203pVJ--sreL75AfKcFXlDoD836PQ-npaT5wuab2P_oKSKLbomkN6Hy-6wleKi3KCTftUjTnbpgbLeCotk8lX7nsPfIUWaIL5GD29Z1winIz2rFso0JA-aRmYcSmZUVq0I5-mnhfjvUAqLEhDRYwSET1SP8Us3qfx0-PKfHVKqxyZ5vwBAOpl6b1eQ3-nEQuaEu9ZnqA_F7IM4XkmFOTjXVurCpCXP__zGvoNo0PPEp7rIE1LeTqwNZK1gLWBt3B_pavLiZWbHRz4jBeV

2024/04/16 23:45:53      verified with TINK PublicKey
2024/04/16 23:45:53      verified with exported PubicKey
2024/04/16 23:45:53      verified with TINK PublicKey

```

#### ECC

Create a key

```log
$ go run ecc/create/keycreate.go 

2024/04/16 23:46:22 Tink Keyset: {
	"primaryKeyId": 3521787698,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
				"value": "EkwSBggDEAIYAhogGUEsWsGn99j5kqhihSNQ9ynJyf02CE1TYoATg6bTc4siIApLCiwNLzIg1aiC8LNM+l6AVcbbF3pfeBGiThV7/PgbGiAu16EOUonJlT8I6xVkalwi4j/dLa/qPTXblsWJkT6y0Q==",
				"keyMaterialType": "ASYMMETRIC_PRIVATE"
			},
			"status": "ENABLED",
			"keyId": 3521787698,
			"outputPrefixType": "RAW"
		}
	]
}
2024/04/16 23:46:22 Created PrimaryKeyId 3521787698
2024/04/16 23:46:22   Found TypeUrl: type.googleapis.com/google.crypto.tink.EcdsaPrivateKey
2024/04/16 23:46:22 Tink Keyset: {
	"primaryKeyId": 3521787698,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
				"value": "EgYIAxACGAIaIBlBLFrBp/fY+ZKoYoUjUPcpycn9NghNU2KAE4Om03OLIiAKSwosDS8yINWogvCzTPpegFXG2xd6X3gRok4Ve/z4Gw==",
				"keyMaterialType": "ASYMMETRIC_PUBLIC"
			},
			"status": "ENABLED",
			"keyId": 3521787698,
			"outputPrefixType": "RAW"
		}
	]
}
2024/04/16 23:46:22   Found TypeUrl: type.googleapis.com/google.crypto.tink.EcdsaPublicKey
2024/04/16 23:46:22 signature verified using tink
2024/04/16 23:46:22 type.googleapis.com/google.crypto.tink.EcdsaPublicKey
2024/04/16 23:46:22 pubkey: 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGUEsWsGn99j5kqhihSNQ9ynJyf02
CE1TYoATg6bTc4sKSwosDS8yINWogvCzTPpegFXG2xd6X3gRok4Ve/z4Gw==
-----END PUBLIC KEY-----

2024/04/16 23:46:22 signature verified using ecc
```


Sign and verify

```log
2024/04/16 23:48:00 ======= Init  ========
2024/04/16 23:48:00 ECC PublicKey: 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGUEsWsGn99j5kqhihSNQ9ynJyf02
CE1TYoATg6bTc4sKSwosDS8yINWogvCzTPpegFXG2xd6X3gRok4Ve/z4Gw==
-----END PUBLIC KEY-----

TOKEN: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzEzMzI1NzQwfQ.UZOLRr1QmHnzsk3s8LeZYl7qosRLxFcBzCjpKZepcl-RFYG0T06S7QCUDuFfWiE80uz-JigW83gP3EcCufC3yA
2024/04/16 23:48:00      verified with TINK PublicKey
2024/04/16 23:48:00      verified with exported PubicKey
2024/04/16 23:48:00      verified with TINK PublicKey
```