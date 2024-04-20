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

Currently only the PrimaryKeyID is used for signing and verification.

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

>> IMPORTANT: this library will only sign and verify using the _primary_ key in the keyset

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

// if you intend to sign with a non primary key, first set it to the primary
//prMgr := keyset.NewManagerFromHandle(privateKeyHandle)
//prMgr.SetPrimary(uint32(*keyID))

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
keyctx, err := tinkjwt.NewTINKContext(ctx, config)

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

// if you want to verify a jwt signed by a non-primary key, set it here
//puMgr := keyset.NewManagerFromHandle(publicKeyHandle)
//puMgr.SetPrimary(uint32(*keyID))

config := &tinkjwt.TINKConfig{
	Key: publicKeyHandle,
}

keyctx, err := tinkjwt.NewTINKContext(ctx, config)

// verify with TINK based publicKey
keyFunc, err := tinkjwt.TINKVerfiyKeyfunc(keyctx, config)

tokenP, err := jwt.Parse(tokenString, keyFunc)
if tokenP.Valid {
	log.Println("     verified with TINK PublicKey")
}
```

See the [example/](example/) folder for end-to-end examples


---


#### RSA

Sign and Verify

```bash
## sign with default primary key
$ go run rsa/main.go  --privK keyset/rsa_2_privatekey_keyset.json --pubK=keyset/rsa_2_public_keyset.json 

		2024/04/18 13:40:26 ======= Init  ========
		2024/04/18 13:40:26 RSA PublicKey: 
		-----BEGIN RSA PUBLIC KEY-----
		MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA2du3+AUj75Sfd0GR/faj
		jacdCEsSqYphLbqDQwknwZLzp44cy4D5s3Mt/2QHHIXcvts9DRYVJOpGctg5VDwJ
		7sBNAPZ9h6J4QW6X5lV7TMa1T+jJwlCg56MCQqxayP+EgOCwk4rV8ZPZH/l0a5nV
		eDZZ3mtrlnxGJ5WCnvjMuT8PxJ4SsDFbPzByphDUMGB4Idieka/arQ9p8efbADO4
		6bQUyv97UW7t8pqb49RnX2b2Xl3878UdulIPymsrr4t05rahh8a7daEB6YLK0tF/
		tTvuK0SYMVZMyLb9VsipeGBePRsMvUKt8f9rwhLmQImAcuDYwfkiGAO9bA/VjxNA
		Z/8klBTw6XdL6uR/RrbCXUYeOPvL4XposPHgNu5EDMF4aga5e7jops6iB9O5Ih3h
		cQd+OETUFsLC7J4QXIeunV5LSOPw33BkgqNxVeFNQeNujPAUSCmO7PmwgVfx75TT
		FQMWdLcJgga/G11hOoKT+zuyF1cVClurqxfFKYUlmKBHAgMBAAE=
		-----END RSA PUBLIC KEY-----

		TOKEN: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzEzNDYyMDg2fQ.iLu-Ke_seOSkReDN_pj0VlcWSMltOyfYqLq9BmsOlgWTWa8xJkR0yQhnKZhqL4-KImKM_u33t1Yx6bHI7es2cnJALPuwCqDHr_8jIygk1I1I6b8tm6B8F6u3nmjQiTPstD9LqJfK6yIuu5fE1AqgIcgFvZp5uYeJQJcg5f3Rg71FQcCSbCJA2rddwWgyxlt-b8XMM46-ATRAmP_Lzng9kLOCXIPCcjhoNkNEq0w2NROjaLNYZ1LtsT7CMHU_5T9U2eRxJWlesZSkPcI9dr3BNlOIgUFqp-Q7KeSTltN9wa1uAc4QzjxEfQnit4oMLb89Bn-Vj66cy_SGuO7Sk528QCJZeNeTtKh9IIzu_4JBfoGzzVT1dk_8_2mlSxLgFsyd4EZZIlpPmXpegc5a_OSzZXbG6rpc-gXeNrlB0u4DYWKvO2sLUraCoe46iQaVw_ld2nuQ44PBPCJxKwEmoIs1BXg0GK7x7zm2ln-3dePSu4Xl0hnaX7diw3PFFvGc6jxC
		2024/04/18 13:40:26      verified with TINK PublicKey
		2024/04/18 13:40:26      verified with exported PubicKey
		2024/04/18 13:40:26      verified with TINK PublicKey


## sign with other named keys
$ go run rsa/main.go --keyID=2174348416 --privK keyset/rsa_2_privatekey_keyset.json --pubK=keyset/rsa_2_public_keyset.json 

		2024/04/18 13:41:31 ======= Init  ========
		2024/04/18 13:41:31 RSA PublicKey: 
		-----BEGIN RSA PUBLIC KEY-----
		MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAkdWeGM94Z+QosZ5UpXSe
		aT/OF3JFJSrvCl8c9dIcL3l7itTzFQkTyMsJ+i91J2jDF7Apj+z9WowrGgcw74Zb
		M56UGql1JbV+TA8Rjv6gtGg/EdGGKJkWrqID72huEaRzyvlxlE1aM2BrScaNvcFs
		CffkrERAi53yhEO/QWZpi02DaRiE0IXd3R2wesckAkYs95xKRLIJ4ID3jf5lDHNC
		q39AdVSy9x2iTZJNwPCAoLLcLNsWEzy2QkvXXdpRyvyWtgEB/de40YT7cppeoPDt
		/5bXSY1HDRfrH9LB77iWdTgfBro8Jqtg+0Bqh3TID4lTSGMeScU5fbsjzkhGlaEi
		5LefA2k+AJnKwdXPaSSRMhRN4Z3u8b3uxjhSnV1ATv9DTJE9kGc4/9SVqOnXBE3e
		OUaoRR1Ax2WXbVBehlb63OqotWbCLzJSeNKBjtrqKo3E53clqZEkcdPu9bCGG0gj
		M5o8aheFU4sP2hItOMHNuIuucG3GWRLA45RZj15FNaFvAgMBAAE=
		-----END RSA PUBLIC KEY-----

		TOKEN: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzEzNDYyMTUxfQ.Zntc0unwXnHYZfDIMZRn3damSJSdmtXuafpfCzYjeKP3IHSbkSvsnv1zTVq2aWayDuafoHECEqZMe_zbCPWiwsgK2_0GmawyI3WCzGfiH9UkdoSCOMyGtg9Ci0M-IXmRH5rHpJU_4LaGIz6PDg4DeHceRxdJntIGqTkxf_fLX9zAR-FALnaWyWX_S_ePMHfb8R248fiQQAt_9bjn04Ye-A7lGsTSVO-HZKJQKqIvy6jLNXEzUBvxvdOqnSBsgn5WuEfzgM5eirehwBebNALPGgNY9WDEjAfiahfrWmB1BYs-EIwKFIZj6HNQLaEol6iR4CDh2avEhTkuw5FSXtkL1DYLcRC8XkcmtdmCjtEEfofura2hpnGu89M3i0g3gmKVxWG8hRDs7cwfmpvIpZ8i9EIQlO-YUi51lc-pv3nUlVBW3FEVXoHWIs7_bC_gk4n6I-UA2asO5CmGkIfUpP6KefiAqozyHvzYWGVHHbR7whmoRaWXR_a_dpXuv9keSv2K
		2024/04/18 13:41:31      verified with TINK PublicKey
		2024/04/18 13:41:31      verified with exported PubicKey
		2024/04/18 13:41:31      verified with TINK PublicKey
```

#### ECC


Sign and verify

```bash
$ go run ecc/main.go  --privK keyset/ecc_1_privatekey_keyset.json --pubK=keyset/ecc_1_public_keyset.json 

		2024/04/18 13:42:19 ======= Init  ========
		2024/04/18 13:42:19 ECC PublicKey: 
		-----BEGIN PUBLIC KEY-----
		MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGOLxcX/cPer+YNwY8MIK68QUT6r6
		XbnUaE5GXGGlqP2hEyHG29u0buqlHr9uY77jOVmCzWATfjTefMW5aRDyZw==
		-----END PUBLIC KEY-----

		TOKEN: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzEzNDYyMTk5fQ.0ViPNc2fUa10WhTfgfY7w1bDhBiUhxGoGBVW6Ox6nffiWQzerQjy92mpF_H1YIzkJoJlQenEtTI_SQf442UEMw
		2024/04/18 13:42:19      verified with TINK PublicKey
		2024/04/18 13:42:19      verified with exported PubicKey
		2024/04/18 13:42:19      verified with TINK PublicKey
```


#### Keyset

This library uses the _primary key_ in a keyset for sign and verify steps.

The `example` folder contains some pre-generated keysets where the rsa keyset has two valid keys.

These keys were created using the following [tinkey](https://developers.google.com/tink/install-tinkey) commands:

```bash
$ tinkey list-key-templates

$ tinkey create-keyset --key-template=RSA_SSA_PKCS1_3072_SHA256_F4 --out-format=json --out=keyset/rsa_1_privatekey_keyset.json
$ tinkey create-public-keyset --in=keyset/rsa_1_privatekey_keyset.json --out-format=json --out=keyset/rsa_1_public_keyset.json


$ tinkey list-keyset --in=keyset/rsa_1_privatekey_keyset.json

primary_key_id: 2174348416
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey"
  status: ENABLED
  key_id: 2174348416
  output_prefix_type: TINK
}


$ tinkey list-keyset --in=keyset/rsa_1_public_keyset.json

primary_key_id: 2174348416
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey"
  status: ENABLED
  key_id: 2174348416
  output_prefix_type: TINK
}

$ tinkey rotate-keyset --key-template=RSA_SSA_PKCS1_3072_SHA256_F4 --in-format=json \
  --in=keyset/rsa_1_privatekey_keyset.json --out-format=json --out=keyset/rsa_1_privatekey_keyset.json

$ tinkey create-public-keyset --in=keyset/rsa_2_privatekey_keyset.json --out-format=json --out=keyset/rsa_2_public_keyset.json

$ tinkey list-keyset --in=keyset/rsa_2_privatekey_keyset.json

primary_key_id: 123569881
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey"
  status: ENABLED
  key_id: 2174348416
  output_prefix_type: TINK
}
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey"
  status: ENABLED
  key_id: 123569881
  output_prefix_type: TINK
}

$ tinkey list-keyset --in=keyset/rsa_2_public_keyset.json

primary_key_id: 123569881
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey"
  status: ENABLED
  key_id: 2174348416
  output_prefix_type: TINK
}
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey"
  status: ENABLED
  key_id: 123569881
  output_prefix_type: TINK
}

### ECC

$ tinkey create-keyset --key-template=ECDSA_P256 --out-format=json --out=keyset/ecc_1_privatekey_keyset.json
$ tinkey create-public-keyset --in=keyset/ecc_1_privatekey_keyset.json --out-format=json --out=keyset/ecc_1_public_keyset.json

$ tinkey create-keyset --key-template=ECDSA_P256_IEEE_P1363_WITHOUT_PREFIX --out-format=json --out=keyset/ecc_2_privatekey_keyset.json
$ tinkey create-public-keyset --in=keyset/ecc_2_privatekey_keyset.json --out-format=json --out=keyset/ecc_2_public_keyset.json

```