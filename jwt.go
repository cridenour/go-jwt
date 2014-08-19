/*
Package jwt provides dead simple encoding and decoding of
the JSON Web Token Draft.

Two default functions are exported. Payloads are exposed as map[string]interface{}.
Default encoding algorithm is SHA256 using HMAC.

	Encode:
		Provide a payload and key. Returns a token.
	Decode:
		Provide a token and key. Returns original payload.

Convenience functions exported are for using specific algorithms for encoding. Only need one Decode.

	EncodeHS256:
		Uses SHA256 with HMAC
	EncodeHS384:
		Uses SHA256 with HMAC
	EncodeHS512:
		Uses SHA512 with HMAC
	EncodeRS256:
		Uses SHA256 with RSA
	EncodeRS384:
		Uses SHA384 with RSA
	EncodeRS512:
		Uses SHA512 with RSA
*/
package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"hash"
	"io"
	"strconv"
	"strings"
)

type Encoding int32

const (
	HMAC Encoding = iota
	RSA
)

type Algorithm struct {
	Func          func() hash.Hash
	CryptoPointer crypto.Hash
}

var algorithmLookup = map[int]Algorithm{
	256: Algorithm{sha256.New, crypto.SHA256},
	384: Algorithm{sha512.New384, crypto.SHA384},
	512: Algorithm{sha512.New, crypto.SHA512},
}

func encode(payload map[string]interface{}, key []byte, algorithm Algorithm, encoding Encoding) (string, error) {
	// Generate our header by checking the hash size and Encoding variable
	header := map[string]interface{}{
		"typ": "JWT",
	}

	var alg string

	if encoding == HMAC {
		alg = "HS"
	} else {
		alg = "RS"
	}

	size := algorithm.Func().Size() * 8
	alg += strconv.Itoa(size)
	header["alg"] = alg

	// Get JSON representations of the header and payload
	// and run through base64 encoding
	segments := []string{}

	segments = append(segments, marshalAndEncode(header))
	segments = append(segments, marshalAndEncode(payload))

	// Sign the payload/header pair
	var signature []byte
	if encoding == HMAC {
		hash := hmac.New(algorithm.Func, key)
		io.WriteString(hash, strings.Join(segments, "."))
		signature = hash.Sum(nil)
	} else {
		hash := algorithm.Func()
		io.WriteString(hash, strings.Join(segments, "."))
		var err error
		rsaKey := generateRSAKey(key)
		signature, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, algorithm.CryptoPointer, hash.Sum(nil))
		if err != nil {
			return "", err
		}
	}

	segments = append(segments, strings.TrimRight(base64.URLEncoding.EncodeToString(signature), "="))

	return strings.Join(segments, "."), nil
}

func Decode(token string, key []byte) map[string]interface{} {
	// Split our token and parse our segments
	segments := strings.SplitN(token, ".", 3)

	header := decodeAndUnmarshal(segments[0])
	payload := decodeAndUnmarshal(segments[1])

	// Determine signature methods
	var algorithm Algorithm
	var ok bool
	var encoding Encoding

	alg := header["alg"].(string)
	if alg[0:1] == "H" {
		encoding = HMAC
	} else {
		encoding = RSA
	}

	algSize, err := strconv.Atoi(alg[2:])
	if err != nil {
		panic("Unable to parse integer from algorithm in header.")
	}

	algorithm, ok = algorithmLookup[algSize]
	if !ok {
		panic("Unable to determine signature method for " + string(alg[2:]))
	}

	// Add padding if we are short
	if p := len(segments[2]) % 4; p != 0 {
		segments[2] += strings.Repeat("=", 4-p)
	}

	signature, err := base64.URLEncoding.DecodeString(segments[2])
	if err != nil {
		panic("Unable to decode signature.")
	}

	if encoding == HMAC {
		hash := hmac.New(algorithm.Func, key)
		io.WriteString(hash, strings.Join(segments[0:2], "."))
		match := subtle.ConstantTimeCompare(hash.Sum(nil), signature)
		if match == 0 {
			panic("Did not pass validation.")
		}
	} else {
		hash := algorithm.Func()
		io.WriteString(hash, strings.Join(segments[0:2], "."))
		pubKey := generatePubKey(key)
		err := rsa.VerifyPKCS1v15(pubKey, algorithm.CryptoPointer, hash.Sum(nil), signature)
		if err != nil {
			panic("Did not pass RSA verification. " + err.Error())
		}
	}

	return payload
}

func marshalAndEncode(payload map[string]interface{}) string {
	data, err := json.Marshal(payload)
	if err != nil {
		panic("Unable to convert payload to JSON.")
	}

	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func decodeAndUnmarshal(s string) map[string]interface{} {
	// Add padding if we are short
	if p := len(s) % 4; p != 0 {
		s += strings.Repeat("=", 4-p)
	}

	data, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		panic("Unable to decode payload or header.")
	}

	var payload map[string]interface{}
	err = json.Unmarshal(data, &payload)
	if err != nil {
		panic("Unable to parse json from payload or header.")
	}

	return payload
}

// Reads in a PEM encoded PKCS1 private key
func generateRSAKey(key []byte) *rsa.PrivateKey {
	// Decode the PEM block from the bytes
	block, _ := pem.Decode(key)
	if block == nil {
		panic("No PEM block present.")
	}

	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("Unable to parse RSA key. Must be a PEM encoded PKCS1 key.")
	}
	return rsaKey
}

// Reads in a PEM encoded PKIX public key
func generatePubKey(key []byte) *rsa.PublicKey {
	// Decode the PEM block from the bytes
	block, _ := pem.Decode(key)
	if block == nil {
		panic("No PEM block present.")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("unable to parse public key. Must be a PEM encoded PKIX key.")
	}
	return pubKey.(*rsa.PublicKey)
}

func EncodeHS256(payload map[string]interface{}, key []byte) (string, error) {
	hasher := algorithmLookup[256]
	return encode(payload, key, hasher, HMAC)
}

func EncodeHS384(payload map[string]interface{}, key []byte) (string, error) {
	hasher := algorithmLookup[384]
	return encode(payload, key, hasher, HMAC)
}

func EncodeHS512(payload map[string]interface{}, key []byte) (string, error) {
	hasher := algorithmLookup[512]
	return encode(payload, key, hasher, HMAC)
}

func EncodeRS256(payload map[string]interface{}, key []byte) (string, error) {
	hasher := algorithmLookup[256]
	return encode(payload, key, hasher, RSA)
}

func EncodeRS384(payload map[string]interface{}, key []byte) (string, error) {
	hasher := algorithmLookup[384]
	return encode(payload, key, hasher, RSA)
}

func EncodeRS512(payload map[string]interface{}, key []byte) (string, error) {
	hasher := algorithmLookup[512]
	return encode(payload, key, hasher, RSA)
}

func Encode(payload map[string]interface{}, key []byte) (string, error) {
	return EncodeHS256(payload, key)
}
