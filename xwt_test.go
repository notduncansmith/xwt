package xwt

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/sign"
)

const epoch = 1583826163

func TestRoundtrip(t *testing.T) {
	kp, err := GenerateKeys(bytes.NewReader([]byte("thisistheroundtriptestsecretkey!thisistheroundtriptestsecretkey!")))
	if err != nil {
		t.Fatalf("Error generating keys: %v", err)
	}

	token, err := NewTokenV1(epoch, []byte("user:12345"), nil)
	token.Sign(kp)
	expectTokenVerified(t, token, kp)
	t2, err := Parse(token.Serialize())
	if err != nil {
		t.Fatalf("Error parsing token: %v", err)
	}
	expectParsedToken(t, token, t2)
}

func TestGenerateKeys(t *testing.T) {
	kp, err := GenerateKeys(nil)
	if err != nil {
		t.Fatalf("Error generating keys: %v", err)
	}
	expectValidKeyPair(t, kp)
}

func TestAutoSign(t *testing.T) {
	kp, err := GenerateKeys(nil)
	if err != nil {
		t.Fatalf("Error generating keys: %v", err)
	}
	token, err := NewTokenV1(epoch, []byte("user:1234"), kp)
	if err != nil {
		t.Fatalf("Error signing token: %v", err)
	}
	if len(token.Signature) != 64 {
		t.Fatalf("Token was not signed %+v", token)
	}
}

func TestJSCompatibility(t *testing.T) {
	bz, _ := hex.DecodeString("104e4a172a8da3526e9c58aef2353a50b5c204a12ed4e3a926e9ba4123bca23a8796f7eeee7ef649b6c4f601b668bb045c1b71408f3530187c25d237b161c30b76313132333435363738393061736466")

	public, _, err := sign.GenerateKey(bytes.NewReader([]byte("asdfasdfasdfasdfasdfasdfasdfasdf")))
	if err != nil {
		t.Fatalf("Could not generate key: %v", err)
	}

	token, err := Parse(bz)
	if err != nil {
		t.Fatalf("Could not parse: %v", err)
	}

	if token.Expires != 1234567890 {
		t.Fatal("Could not parse: bad expires")
	}

	if string(token.ID) != "asdf" {
		t.Fatal("Could not parse: bad id")
	}

	if err = token.Verify(*public, 99999*time.Hour); err != nil {
		t.Fatal("Could not verify parsed token")
	}
}

func expectTokenVerified(t *testing.T, token *Token, kp *KeyPair) {
	sinceEpoch := time.Now().Sub(time.Unix(epoch, 0))
	if err := token.Verify(*kp.PublicKey, sinceEpoch+time.Second); err != nil {
		t.Fatalf("Error verifying token: %v", err)
	}
}

func expectParsedToken(t *testing.T, expected *Token, actual *Token) {
	if expected.Version != actual.Version {
		t.Fatalf("Parsed token Version does not match: (expected %v, got %v)", actual.Version, expected.Version)
	}

	if expected.Expires != actual.Expires {
		t.Fatalf("Parsed token Expires does not match: (expected %v, got %v)", actual.Expires, expected.Expires)
	}

	if string(expected.ID) != string(actual.ID) {
		t.Fatalf("Parsed token ID does not match: (expected %v, got %v)", actual.ID, expected.ID)
	}

	if string(expected.Signature) != string(actual.Signature) {
		t.Fatalf("Parsed token Signature does not match: (expected %v, got %v)", actual.Signature, expected.Signature)
	}
}

func expectValidKeyPair(t *testing.T, kp *KeyPair) {
	if len(kp.PrivateKey) != 64 || len(kp.PrivateHex()) != 128 {
		t.Fatalf("Generated invalid private key: %+v", *kp)
	}
	if len(kp.PublicKey) != 32 || len(kp.PublicHex()) != 64 {
		t.Fatalf("Generated invalid public key: %+v", *kp)
	}
}
