package base64url

import (
	"encoding/base64"
	"encoding/json"
)

// A Value holds octets that can be serialized to a base64url-encoded
// string, without padding.
type Value struct {
	octets []byte
}

// NewValue creates a new Value.
func NewValue(data []byte) *Value {
	if data == nil {
		return nil
	}

	return &Value{data}
}

// Bytes returns the raw, unencoded octets.
func (val *Value) Bytes() []byte {
	return val.octets
}

// MarshalJSON implements the json.Marshaler interface.
func (val *Value) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(val.octets))
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (val *Value) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}

	octets, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return err
	}

	*val = Value{octets}
	return nil
}
