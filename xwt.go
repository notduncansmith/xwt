package xwt

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"golang.org/x/crypto/nacl/sign"
)

const signatureLength = 64
const versionLength = 2
const expiresLength = 10

// PublicKey is an NaCl-compatible public key
type PublicKey = *[32]byte

// PrivateKey is an NaCl-compatible private key
type PrivateKey = *[64]byte

// KeyPair is an NaCl-compatible public/private keypair
type KeyPair struct {
	PublicKey
	PrivateKey
}

// PublicHex returns a hex-encoded string containing the public key
func (kp KeyPair) PublicHex() string {
	return hex.EncodeToString(kp.PublicKey[:])
}

// PrivateHex returns a hex-encoded string containing the private key
func (kp KeyPair) PrivateHex() string {
	return hex.EncodeToString(kp.PrivateKey[:])
}

// SerializedToken represents a token in the format (signature | version | expires | id)
type SerializedToken = []byte

// Token represents a token
type Token struct {
	Signature []byte
	Data      []byte
	Version   int
	Expires   int64
	ID        []byte
}

// NewTokenV1 returns a Token with the given values. If a KeyPair is given, the returned Token will be signed.
func NewTokenV1(expires int64, id []byte, kp *KeyPair) (*Token, error) {
	t := Token{Version: 1, Expires: expires, ID: id}
	t.serializeData()
	if kp != nil {
		t.Sign(kp)
	}
	return &t, nil
}

// Parse extracts the information from a SerializedToken
func Parse(bz SerializedToken) (*Token, error) {
	signatureBz := bz[:signatureLength]
	versionBz := bz[signatureLength:(signatureLength + versionLength)]
	expiresBz := bz[(signatureLength + versionLength):(signatureLength + versionLength + expiresLength)]
	idBz := bz[(signatureLength + versionLength + expiresLength):]

	if string(versionBz) != "v1" {
		return nil, fmt.Errorf("Invalid token version: %v (%v)", string(bz), string(versionBz))
	}
	expires, err := stri64(string(expiresBz))
	if err != nil {
		return nil, fmt.Errorf("Error parsing expiry: %v %v", string(bz), err)
	}
	t := Token{
		Data:      bz[signatureLength:],
		Signature: signatureBz,
		Version:   1,
		Expires:   expires,
		ID:        idBz,
	}
	return &t, nil
}

// Serialize encodes a Token as bytes in the format (signature | version | expires | id)
func (t *Token) Serialize() SerializedToken {
	t.serializeData()
	bz := make([]byte, signatureLength+len(t.Data))
	copy(bz[:signatureLength], t.Signature)
	copy(bz[signatureLength:], t.Data)
	return bz
}

// serializeData encodes the non-signature data of a Token as bytes in the format (version | expires | id)
func (t *Token) serializeData() []byte {
	if len(t.Data) > 0 {
		return t.Data
	}
	bz := make([]byte, versionLength+expiresLength+len(t.ID))
	copy(bz[:versionLength], []byte(fmt.Sprintf("v%v", t.Version)))
	expiresBz := []byte(i64str(t.Expires))
	copy(bz[versionLength:(versionLength+expiresLength)], expiresBz)
	copy(bz[(versionLength+expiresLength):], t.ID)
	t.Data = bz
	return bz
}

// Sign signs the non-signature data and sets the signature
func (t *Token) Sign(kp *KeyPair) {
	t.serializeData()
	signed := sign.Sign(nil, t.Data, kp.PrivateKey)
	t.Signature = signed[:signatureLength]
}

// Verify returns an error if a token is not valid
func (t *Token) Verify(pubkey [32]byte, expiryGracePeriod time.Duration) error {
	sigWithMessage := make([]byte, len(t.Signature)+len(t.Data))
	copy(sigWithMessage[:signatureLength], t.Signature)
	copy(sigWithMessage[signatureLength:], t.Data)

	_, valid := sign.Open(nil, sigWithMessage, &pubkey)
	if !valid {
		return errors.New("Invalid signature")
	}
	finalExpiry := time.Unix(t.Expires, 0).Add(expiryGracePeriod)
	if time.Now().After(finalExpiry) {
		return errors.New("Expired token")
	}
	return nil
}

// GenerateKeys generates and returns a KeyPair
func GenerateKeys(from io.Reader) (*KeyPair, error) {
	if from == nil {
		public, private, err := sign.GenerateKey(rand.Reader)
		return &KeyPair{PublicKey: public, PrivateKey: private}, err
	}
	public, private, err := sign.GenerateKey(from)
	return &KeyPair{PublicKey: public, PrivateKey: private}, err
}

func i64str(i int64) string {
	return strconv.FormatInt(i, 10)
}

func stri64(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}
