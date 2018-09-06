package base64url

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"
)

func testEncoding(t *testing.T, val *Value, data []byte, expected string) {
	if !bytes.Equal(val.Bytes(), data) {
		t.Fatalf("invalid value for %v: %v", data, val.Bytes())
	}

	encoded, err := json.Marshal(val)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if string(encoded) != expected {
		t.Fatal("unexpected encoded value:", string(encoded))
	}

	decoded := new(Value)
	err = json.Unmarshal(encoded, decoded)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !bytes.Equal(decoded.Bytes(), data) {
		t.Fatalf("decoding error: want %v, got %v", data, decoded.Bytes())
	}
}

func TestValue(t *testing.T) {
	// Test vectors from Appendix C of RFC 7515
	data := []byte{3, 236, 255, 224, 193}
	expected := `"A-z_4ME"`

	testEncoding(t, NewValue(data), data, expected)
}

func TestUint64(t *testing.T) {
	cases := []struct {
		x       uint64
		octets  []byte
		encoded string
	}{
		{0, []byte{0}, `"AA"`},             // RFC 7515, Section 2
		{65537, []byte{1, 0, 1}, `"AQAB"`}, // RFC 7515, Section 6.3.1.2
	}

	for _, c := range cases {
		testEncoding(t, NewUint64(c.x), c.octets, c.encoded)
	}
}

func TestZero(t *testing.T) {
	bigZero := NewBigInt(big.NewInt(0))
	if len(bigZero.Bytes()) != 0 {
		t.Error("octets for zero big.Int should be an empty slice")
	}

	uintZero := NewUint64(0)
	if len(uintZero.Bytes()) != 1 && uintZero.Bytes()[0] != 0 {
		t.Error("octets for zero big.Int should be byte{0}")
	}

	if bigZero.Uint64() != uintZero.Uint64() {
		t.Error("zero values are not equal")
	}
}
