package base64url

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestValue(t *testing.T) {
	// Test vectors from Appendix C of RFC 7515
	data := []byte{3, 236, 255, 224, 193}

	val := NewValue(data)
	if !bytes.Equal(val.Bytes(), data) {
		t.Fatalf("invalid value for %v: %v", data, val.Bytes())
	}

	encoded, err := json.Marshal(val)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if string(encoded) != `"A-z_4ME"` {
		t.Fatal("expected encoded value:", string(encoded))
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
