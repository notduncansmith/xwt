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

	if err := token.Sign(kp); err != nil {
		t.Fatalf("Error signing token: %v", err)
	}

	sinceEpoch := time.Now().Sub(time.Unix(1583826163, 0))
	if err = token.Verify(*kp.PublicKey, sinceEpoch+time.Second); err != nil {
		t.Fatalf("Error verifying token: %v", err)
	}
}
