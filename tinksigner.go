package tinkjwt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/tink-crypto/tink-go/v2/keyset"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	rsppb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	rspsspb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pss_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/signature"
	"google.golang.org/protobuf/proto"
)

const (
	rsaPKCS1PrivateKeyTypeURL  = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey"
	rsaSSAPKCS1VerifierTypeURL = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey"

	rsaPSSPrivateKeyTypeURL    = "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey"
	rsaPSSPKCS1VerifierTypeURL = "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey"

	ecdsaVerifierTypeURL   = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
	ecdsaPrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"

	// https://github.com/google/tink/blob/master/go/core/cryptofmt/cryptofmt.go#L68
	// NonRawPrefixSize is the prefix size of Tink and Legacy key types.
	NonRawPrefixSize = 5

	// TinkPrefixSize is the prefix size of Tink key types.
	// The prefix starts with \x01 and followed by a 4-byte key id.
	TinkPrefixSize = NonRawPrefixSize
	// TinkStartByte is the first byte of the prefix of Tink key types.
	TinkStartByte = byte(1)

	// RawPrefixSize is the prefix size of Raw key types.
	// Raw prefix is empty.
	RawPrefixSize = 0
	// RawPrefix is the empty prefix of Raw key types.
	RawPrefix = ""
)

type TINKConfig struct {
	Key               *keyset.Handle
	KeyID             string           // (optional) the keyID (eg, specify the 'kid' parameter; if not set, use the TINK primary keyID)
	publicKeyFromTINK crypto.PublicKey // the public key as read from KeyHandleFile, KeyHandleNV
}

type tinkConfigKey struct{}

func (k *TINKConfig) GetKeyID() string {
	return k.KeyID
}

func (k *TINKConfig) GetPublicKey() crypto.PublicKey {
	return k.publicKeyFromTINK
}

var (
	SigningMethodTINKRS256 *SigningMethodTINK
	SigningMethodTINKPS256 *SigningMethodTINK
	SigningMethodTINKES256 *SigningMethodTINK
	errMissingConfig       = errors.New("tinkjwt: missing configuration in provided context")
)

type SigningMethodTINK struct {
	alg      string
	override jwt.SigningMethod
	hasher   crypto.Hash
}

func bytesToBigInt(v []byte) *big.Int {
	return new(big.Int).SetBytes(v)
}

// https://github.com/google/tink/blob/master/go/core/cryptofmt/cryptofmt.go#L68
func createOutputPrefix(size int, startByte byte, keyID uint32) string {
	prefix := make([]byte, size)
	prefix[0] = startByte
	binary.BigEndian.PutUint32(prefix[1:], keyID)
	return string(prefix)
}

func NewTINKContext(parent context.Context, val *TINKConfig) (context.Context, error) {
	// first check if a TPM is even involved in the picture here since we can verify w/o a TPM
	if val.Key == nil {
		return nil, fmt.Errorf("tinkjwt: tpm device or key not set")
	}
	// TODO: find a better way to manage the keyset
	//  for now, only use the primary key
	for _, k := range val.Key.KeysetInfo().GetKeyInfo() {
		if val.Key.KeysetInfo().PrimaryKeyId == k.KeyId {
			if val.KeyID == "" {
				val.KeyID = fmt.Sprint(k.KeyId)
			}

			if k.Status != tinkpb.KeyStatusType_ENABLED {
				return nil, fmt.Errorf("key is not ENABLED %d", k.KeyId)
			}
			// look for the primary key in the keyset
			if k.OutputPrefixType != tinkpb.OutputPrefixType_RAW && k.OutputPrefixType != tinkpb.OutputPrefixType_TINK {
				return nil, fmt.Errorf("outputPrefix type must be either RAW or TINK; got %v", k.OutputPrefixType)
			}
			switch k.TypeUrl {
			case rsaPKCS1PrivateKeyTypeURL, rsaPSSPrivateKeyTypeURL:

				publicKeyHandle, err := val.Key.Public()
				if err != nil {
					return nil, fmt.Errorf("could not acquire public Keyhandle %v", err)
				}
				bbw := new(bytes.Buffer)
				bw := keyset.NewBinaryWriter(bbw)
				err = publicKeyHandle.WriteWithNoSecrets(bw)
				if err != nil {
					return nil, fmt.Errorf("could not write encrypted keyhandle %v", err)
				}

				tpb := &tinkpb.Keyset{}

				err = proto.Unmarshal(bbw.Bytes(), tpb)
				if err != nil {
					return nil, fmt.Errorf("could not unmarshall keyhandle %v", err)
				}

				for _, kk := range tpb.Key {
					if kk.KeyId == val.Key.KeysetInfo().PrimaryKeyId {
						kserialized := kk.KeyData.Value

						if k.TypeUrl == rsaPKCS1PrivateKeyTypeURL {
							key := &rsppb.RsaSsaPkcs1PublicKey{}
							if err := proto.Unmarshal(kserialized, key); err != nil {
								return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
							}

							pubKey := &rsa.PublicKey{
								E: int(bytesToBigInt(key.GetE()).Int64()),
								N: bytesToBigInt(key.GetN()),
							}
							val.publicKeyFromTINK = pubKey
						} else if k.TypeUrl == rsaPSSPrivateKeyTypeURL {
							key := &rspsspb.RsaSsaPssPublicKey{}
							if err := proto.Unmarshal(kserialized, key); err != nil {
								return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
							}

							pubKey := &rsa.PublicKey{
								E: int(bytesToBigInt(key.GetE()).Int64()),
								N: bytesToBigInt(key.GetN()),
							}
							val.publicKeyFromTINK = pubKey
						} else {
							return nil, fmt.Errorf("error: unknown private key type")
						}

					}
				}

			case rsaSSAPKCS1VerifierTypeURL, rsaPSSPKCS1VerifierTypeURL:

				bbw := new(bytes.Buffer)
				bw := keyset.NewBinaryWriter(bbw)
				err := val.Key.WriteWithNoSecrets(bw)
				if err != nil {
					return nil, fmt.Errorf("could not write encrypted keyhandle %v", err)
				}

				tpb := &tinkpb.Keyset{}

				err = proto.Unmarshal(bbw.Bytes(), tpb)
				if err != nil {
					return nil, fmt.Errorf("could not unmarshall keyhandle %v", err)
				}

				for _, kk := range tpb.Key {
					if kk.KeyId == val.Key.KeysetInfo().PrimaryKeyId {
						kserialized := kk.KeyData.Value
						if k.TypeUrl == rsaSSAPKCS1VerifierTypeURL {
							key := &rsppb.RsaSsaPkcs1PublicKey{}
							if err := proto.Unmarshal(kserialized, key); err != nil {
								return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
							}

							pubKey := &rsa.PublicKey{
								E: int(bytesToBigInt(key.GetE()).Int64()),
								N: bytesToBigInt(key.GetN()),
							}
							val.publicKeyFromTINK = pubKey
						} else if k.TypeUrl == rsaPSSPKCS1VerifierTypeURL {
							key := &rspsspb.RsaSsaPssPublicKey{}
							if err := proto.Unmarshal(kserialized, key); err != nil {
								return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
							}

							pubKey := &rsa.PublicKey{
								E: int(bytesToBigInt(key.GetE()).Int64()),
								N: bytesToBigInt(key.GetN()),
							}
							val.publicKeyFromTINK = pubKey

						} else {
							return nil, fmt.Errorf("error: unknown public key type")
						}

					}
				}

			case ecdsaPrivateKeyTypeURL:

				publicKeyHandle, err := val.Key.Public()
				if err != nil {
					return nil, fmt.Errorf("could not acquire public Keyhandle %v", err)
				}
				bbw := new(bytes.Buffer)
				bw := keyset.NewBinaryWriter(bbw)
				err = publicKeyHandle.WriteWithNoSecrets(bw)
				if err != nil {
					return nil, fmt.Errorf("could not write encrypted keyhandle %v", err)
				}

				tpb := &tinkpb.Keyset{}

				err = proto.Unmarshal(bbw.Bytes(), tpb)
				if err != nil {
					return nil, fmt.Errorf("could not unmarshall keyhandle %v", err)
				}

				for _, kk := range tpb.Key {
					if kk.KeyId == val.Key.KeysetInfo().PrimaryKeyId {
						kserialized := kk.KeyData.Value

						key := &ecdsapb.EcdsaPublicKey{}
						if err := proto.Unmarshal(kserialized, key); err != nil {
							return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
						}

						if key.Params.GetCurve() == commonpb.EllipticCurveType_NIST_P256 {
							pubKey := &ecdsa.PublicKey{
								Curve: elliptic.P256(),
								X:     bytesToBigInt(key.X),
								Y:     bytesToBigInt(key.Y),
							}
							val.publicKeyFromTINK = pubKey
						}
					} else {
						return nil, fmt.Errorf("unsupported keytype %v", err)
					}
				}

			case ecdsaVerifierTypeURL:

				bbw := new(bytes.Buffer)
				bw := keyset.NewBinaryWriter(bbw)
				err := val.Key.WriteWithNoSecrets(bw)
				if err != nil {
					return nil, fmt.Errorf("could not write encrypted keyhandle %v", err)
				}

				tpb := &tinkpb.Keyset{}

				err = proto.Unmarshal(bbw.Bytes(), tpb)
				if err != nil {
					return nil, fmt.Errorf("could not unmarshall keyhandle %v", err)
				}

				for _, kk := range tpb.Key {
					if kk.KeyId == val.Key.KeysetInfo().PrimaryKeyId {
						kserialized := kk.KeyData.Value

						key := &ecdsapb.EcdsaPublicKey{}
						if err := proto.Unmarshal(kserialized, key); err != nil {
							return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
						}

						if key.Params.GetCurve() == commonpb.EllipticCurveType_NIST_P256 {
							pubKey := &ecdsa.PublicKey{
								Curve: elliptic.P256(),
								X:     bytesToBigInt(key.X),
								Y:     bytesToBigInt(key.Y),
							}
							val.publicKeyFromTINK = pubKey
						} else {
							return nil, fmt.Errorf("unsupported keytype %v", err)
						}
					}
				}
			default:
				return nil, fmt.Errorf("tinkjwt: error extracting public key %s", k.TypeUrl)
			}
			return context.WithValue(parent, tinkConfigKey{}, val), nil
		}
	}
	return nil, fmt.Errorf("tinkjwt: primary keyID in keyset not found")
}

func TINKFromContext(ctx context.Context) (*TINKConfig, bool) {
	val, ok := ctx.Value(tinkConfigKey{}).(*TINKConfig)
	return val, ok
}

func init() {
	// RS256
	SigningMethodTINKRS256 = &SigningMethodTINK{
		"TINKRS256",
		jwt.SigningMethodRS256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodTINKRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodTINKRS256
	})

	// PS256
	SigningMethodTINKPS256 = &SigningMethodTINK{
		"TINKPS256",
		jwt.SigningMethodPS256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodTINKPS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodTINKPS256
	})

	// ES256
	SigningMethodTINKES256 = &SigningMethodTINK{
		"TINKES256",
		jwt.SigningMethodES256,
		crypto.SHA256,
	}
	jwt.RegisterSigningMethod(SigningMethodTINKES256.Alg(), func() jwt.SigningMethod {
		return SigningMethodTINKES256
	})
}

// Alg will return the JWT header algorithm identifier this method is configured for.
func (s *SigningMethodTINK) Alg() string {
	return s.alg
}

// Override will override the default JWT implementation of the signing function this Cloud KMS type implements.
func (s *SigningMethodTINK) Override() {
	s.alg = s.override.Alg()
	jwt.RegisterSigningMethod(s.alg, func() jwt.SigningMethod {
		return s
	})
}

func (s *SigningMethodTINK) Hash() crypto.Hash {
	return s.hasher
}

func (s *SigningMethodTINK) Sign(signingString string, key interface{}) ([]byte, error) {
	var ctx context.Context

	switch k := key.(type) {
	case context.Context:
		ctx = k
	default:
		return nil, jwt.ErrInvalidKey
	}
	config, ok := TINKFromContext(ctx)
	if !ok {
		return nil, errMissingConfig
	}

	signer, err := signature.NewSigner(config.Key)
	if err != nil {
		return nil, fmt.Errorf("error getting signer %v", err)
	}

	ss, err := signer.Sign([]byte(signingString))
	if err != nil {
		return nil, fmt.Errorf("error signing %v", err)
	}

	for _, k := range config.Key.KeysetInfo().GetKeyInfo() {
		if config.Key.KeysetInfo().PrimaryKeyId == k.KeyId {

			// remove the TINK Prefix
			if k.OutputPrefixType == tinkpb.OutputPrefixType_TINK {
				pf := createOutputPrefix(TinkPrefixSize, TinkStartByte, config.Key.KeysetInfo().PrimaryKeyId)
				ss = ss[len(pf):]
			}

			switch k.TypeUrl {
			case rsaPKCS1PrivateKeyTypeURL, rsaPSSPrivateKeyTypeURL:
				return ss, err
			case ecdsaPrivateKeyTypeURL:
				publicKeyHandle, err := config.Key.Public()
				if err != nil {
					return nil, fmt.Errorf("could not acquire public Keyhandle %v", err)
				}
				bbw := new(bytes.Buffer)
				bw := keyset.NewBinaryWriter(bbw)
				err = publicKeyHandle.WriteWithNoSecrets(bw)
				if err != nil {
					return nil, fmt.Errorf("could not write encrypted keyhandle %v", err)
				}

				tpb := &tinkpb.Keyset{}

				err = proto.Unmarshal(bbw.Bytes(), tpb)
				if err != nil {
					return nil, fmt.Errorf("could not unmarshall keyhandle %v", err)
				}

				for _, kk := range tpb.Key {
					kserialized := kk.KeyData.Value

					key := &ecdsapb.EcdsaPublicKey{}
					if err := proto.Unmarshal(kserialized, key); err != nil {
						return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
					}
					if key.Params.Encoding == ecdsapb.EcdsaSignatureEncoding_IEEE_P1363 {
						return ss, nil
					}
					if key.Params.GetCurve() == commonpb.EllipticCurveType_NIST_P256 {
						curveBits := elliptic.P256().Params().BitSize
						keyBytes := curveBits / 8
						if curveBits%8 > 0 {
							keyBytes += 1
						}
						out := make([]byte, 2*keyBytes)
						var sigStruct struct{ R, S *big.Int }
						_, err = asn1.Unmarshal(ss, &sigStruct)
						if err != nil {
							return nil, fmt.Errorf("tinkjwt: can't unmarshall ecc struct %v", err)
						}
						sigStruct.R.FillBytes(out[0:keyBytes])
						sigStruct.S.FillBytes(out[keyBytes:])
						return out, nil
					} else {
						return nil, fmt.Errorf("unsupported keytype %v", err)
					}
				}
			default:
				return nil, fmt.Errorf("tinkjwt: error extracting publcic key %s", k.TypeUrl)
			}
		}

	}
	return ss, err
}

func TINKVerfiyKeyfunc(ctx context.Context, config *TINKConfig) (jwt.Keyfunc, error) {
	return func(token *jwt.Token) (interface{}, error) {
		return config.publicKeyFromTINK, nil
	}, nil
}

func (s *SigningMethodTINK) Verify(signingString string, signature []byte, key interface{}) error {
	return s.override.Verify(signingString, []byte(signature), key)
}
