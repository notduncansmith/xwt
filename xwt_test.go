package xwt

import (
	"bytes"
	"testing"
	"time"
)

func TestRoundtrip(t *testing.T) {
	kp, err := GenerateKeys(bytes.NewReader([]byte("thisistheroundtriptestsecretkey!thisistheroundtriptestsecretkey!")))
	if err != nil {
		t.Fatalf("Error generating keys: %v", err)
	}

	token, err := NewTokenV1(1583826163, []byte("user:12345"), nil)

	token.Sign(kp)

	sinceEpoch := time.Now().Sub(time.Unix(1583826163, 0))
	if err = token.Verify(*kp.PublicKey, sinceEpoch+time.Second); err != nil {
		t.Fatalf("Error verifying token: %v", err)
	}

	t2, err := Parse(token.Serialize())
	if err != nil {
		t.Fatalf("Error parsing token: %v", err)
	}

	if t2.Version != token.Version {
		t.Fatalf("Parsed token Version does not match: (expected %v, got %v)", token.Version, t2.Version)
	}

	if t2.Expires != token.Expires {
		t.Fatalf("Parsed token Expires does not match: (expected %v, got %v)", token.Expires, t2.Expires)
	}

	if string(t2.ID) != string(token.ID) {
		t.Fatalf("Parsed token ID does not match: (expected %v, got %v)", token.ID, t2.ID)
	}

	if string(t2.Signature) != string(token.Signature) {
		t.Fatalf("Parsed token Signature does not match: (expected %v, got %v)", token.Signature, t2.Signature)
	}
}
