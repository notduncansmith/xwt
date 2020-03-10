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
	Data      []byte
	Signature []byte
	Version   int
	Expires   int64
	ID        []byte
}

// Parse extracts the information from a SerializedToken
func Parse(bz SerializedToken) (*Token, error) {
	signatureBz := bz[:64]
	versionBz := bz[64:66]
	expiresBz := bz[66:74]
	idBz := bz[74:]

	if string(versionBz) != "v1" {
		return nil, fmt.Errorf("Invalid token version: %v", string(bz))
	}
	expires, err := strconv.ParseInt(string(expiresBz), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Error parsing expiry: %v %v", string(bz), err)
	}
	t := Token{
		Data:      bz,
		Signature: signatureBz,
		Version:   1,
		Expires:   expires,
		ID:        idBz,
	}
	return &t, nil
}

// Verify returns an error if a token is not valid
func (t Token) Verify(pubkey [32]byte, expiryGracePeriod time.Duration) error {
	signedBz := make([]byte, len(t.Data)+signatureLength)
	copy(signedBz[:signatureLength], t.Signature[:])
	copy(signedBz[signatureLength:], t.Data[:])
	_, valid := sign.Open(nil, signedBz, &pubkey)
	if !valid {
		return errors.New("Invalid signature")
	}
	finalExpiry := time.Unix(t.Expires, 0).Add(expiryGracePeriod)
	if time.Now().After(finalExpiry) {
		return errors.New("Expired token")
	}
	return nil
}

// Serialize encodes a Token as bytes in the format (signature | version | expires | id)
func (t Token) Serialize() []byte {
	bz := make([]byte, signatureLength+versionLength+expiresLength+len(t.ID))
	copy(bz[:64], t.Signature)
	bz = append(bz, t.SerializeData()...)
	return bz
}

// SerializeData encodes the non-signature data of a Token as bytes in the format (version | expires | id)
func (t Token) SerializeData() []byte {
	bz := make([]byte, versionLength+expiresLength+len(t.ID))
	copy(bz[0:2], []byte(fmt.Sprintf("v%v", t.Version)))
	expiresBz := []byte(strconv.FormatInt(t.Expires, 10))
	copy(bz[2:12], expiresBz)
	copy(bz[12:], t.ID)
	return bz
}

// Sign signs the non-signature data and sets the signature
func (t Token) Sign(kp *KeyPair) error {
	signed := sign.Sign(nil, t.SerializeData(), kp.PrivateKey)
	var signature [64]byte
	copy(signature[:], signed[:64])
	t.Signature = signature[:]
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
