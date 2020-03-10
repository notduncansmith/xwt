package xwt

import (
	"bytes"
	"fmt"
	"testing"
)

func TestRoundtrip(t *testing.T) {
	kp, err := GenerateKeys(bytes.NewReader([]byte("thisistheroundtriptestsecretkey!thisistheroundtriptestsecretkey!")))
	if err != nil {
		t.Fatalf("Error generating keys: %v", err)
	}

	token := Token{
		ID:      []byte("user:12345"),
		Expires: 1583826163,
		Version: 1,
	}

	if err = token.Sign(kp); err != nil {
		t.Fatalf("Error signing token: %v", err)
	}

	fmt.Println("Keys:", kp.PublicHex())
	panic("ono")
}
