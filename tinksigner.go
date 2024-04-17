package tinkjwt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/tink-crypto/tink-go/v2/keyset"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	rsppb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/signature"
	"google.golang.org/protobuf/proto"
)

const (
	rsaPKCS1PrivateKeyTypeURL  = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey"
	rsaSSAPKCS1VerifierTypeURL = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey"

	ecdsaVerifierTypeURL   = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
	ecdsaPrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
)

type TINKConfig struct {
	Key               *keyset.Handle
	publicKeyFromTINK crypto.PublicKey // the public key as read from KeyHandleFile, KeyHandleNV
}

type tinkConfigKey struct{}

func (k *TINKConfig) GetKeyID() string {
	return k.GetKeyID()
}

func (k *TINKConfig) GetPublicKey() crypto.PublicKey {
	return k.publicKeyFromTINK
}

var (
	SigningMethodTINKRS256 *SigningMethodTINK
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

func NewTINKContext(parent context.Context, val *TINKConfig) (context.Context, error) {
	// first check if a TPM is even involved in the picture here since we can verify w/o a TPM
	if val.Key == nil {
		return nil, fmt.Errorf("tinkjwt: tpm device or key not set")
	}

	for _, k := range val.Key.KeysetInfo().GetKeyInfo() {

		switch k.TypeUrl {
		case rsaPKCS1PrivateKeyTypeURL:

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
				kserialized := kk.KeyData.Value

				key := &rsppb.RsaSsaPkcs1PublicKey{}
				if err := proto.Unmarshal(kserialized, key); err != nil {
					return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
				}

				pubKey := &rsa.PublicKey{
					E: int(bytesToBigInt(key.GetE()).Int64()),
					N: bytesToBigInt(key.GetN()),
				}
				val.publicKeyFromTINK = pubKey
			}

		case rsaSSAPKCS1VerifierTypeURL:

			bbw := new(bytes.Buffer)
			bw := keyset.NewBinaryWriter(bbw)
			err := val.Key.WriteWithNoSecrets(bw)
			if err != nil {
				return nil, fmt.Errorf("Could not write encrypted keyhandle %v", err)
			}

			tpb := &tinkpb.Keyset{}

			err = proto.Unmarshal(bbw.Bytes(), tpb)
			if err != nil {
				return nil, fmt.Errorf("could not unmarshall keyhandle %v", err)
			}

			for _, kk := range tpb.Key {
				kserialized := kk.KeyData.Value

				key := &rsppb.RsaSsaPkcs1PublicKey{}
				if err := proto.Unmarshal(kserialized, key); err != nil {
					return nil, fmt.Errorf("Could not write unmarshall publicKey %v", err)
				}

				pubKey := &rsa.PublicKey{
					E: int(bytesToBigInt(key.GetE()).Int64()),
					N: bytesToBigInt(key.GetN()),
				}
				val.publicKeyFromTINK = pubKey
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
				kserialized := kk.KeyData.Value

				key := &ecdsapb.EcdsaPublicKey{}
				if err := proto.Unmarshal(kserialized, key); err != nil {
					return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
				}

				if key.Params.GetCurve() == commonpb.EllipticCurveType_NIST_P256 {
					//digest := sha256.Sum256(data)
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
				kserialized := kk.KeyData.Value

				key := &ecdsapb.EcdsaPublicKey{}
				if err := proto.Unmarshal(kserialized, key); err != nil {
					return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
				}

				if key.Params.GetCurve() == commonpb.EllipticCurveType_NIST_P256 {
					//digest := sha256.Sum256(data)
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

		default:
			return nil, fmt.Errorf("tinkjwt: error extracting publcic key %s", k.TypeUrl)
		}

	}

	return context.WithValue(parent, tinkConfigKey{}, val), nil
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

		switch k.TypeUrl {
		case rsaPKCS1PrivateKeyTypeURL:
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
