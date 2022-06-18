package pgproto3

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgio"
)

// AuthenticationMD5Password is a message sent from the backend indicating that an MD5 hashed password is required.
type AuthenticationSM3Password struct {
	Salt [4]byte
}

// Backend identifies this message as sendable by the PostgreSQL backend.
func (*AuthenticationSM3Password) Backend() {}

// Backend identifies this message as an authentication response.
func (*AuthenticationSM3Password) AuthenticationResponse() {}

// Decode decodes src into dst. src must contain the complete message with the exception of the initial 1 byte message
// type identifier and 4 byte message length.
func (dst *AuthenticationSM3Password) Decode(src []byte) error {
	fmt.Println("AuthenticationSM3Password len", len(src))
	if len(src) != 8 {
		return errors.New("bad authentication message size")
	}

	authType := binary.BigEndian.Uint32(src)

	if authType != AuthTypeSM3Password {
		return errors.New("bad auth type")
	}

	copy(dst.Salt[:], src[4:8])

	return nil
}

// Encode encodes src into dst. dst will include the 1 byte message type identifier and the 4 byte message length.
func (src *AuthenticationSM3Password) Encode(dst []byte) []byte {
	dst = append(dst, 'R')
	dst = pgio.AppendInt32(dst, 12)
	dst = pgio.AppendUint32(dst, AuthTypeSM3Password)
	dst = append(dst, src.Salt[:]...)
	return dst
}

// MarshalJSON implements encoding/json.Marshaler.
func (src AuthenticationSM3Password) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type string
		Salt [4]byte
	}{
		Type: "AuthTypeSM3Password",
		Salt: src.Salt,
	})
}

// UnmarshalJSON implements encoding/json.Unmarshaler.
func (dst *AuthenticationSM3Password) UnmarshalJSON(data []byte) error {
	// Ignore null, like in the main JSON package.
	if string(data) == "null" {
		return nil
	}

	var msg struct {
		Type string
		Salt [4]byte
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return err
	}

	dst.Salt = msg.Salt
	return nil
}
