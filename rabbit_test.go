package rabbit

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRabbit(t *testing.T) {
	var key []byte
	var err error

	r := newRabbit()

	key, err = decodeOSstring("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
	require.NoError(t, err, "hex decode key")

	require.NoError(t, r.setupKey(key), "setupKey should not error with a valid key")
	require.Equal(t, "B15754F036A5D6ECF56B45261C4AF702", encodeOSstring(r.keyStream()), "keyStream should return the proper test vector values")
	require.Equal(t, "88E8D815C59C0C397B696C4789C68AA7", encodeOSstring(r.keyStream()), "keyStream should return the proper test vector values")
	require.Equal(t, "F416A1C3700CD451DA68D1881673D696", encodeOSstring(r.keyStream()), "keyStream should return the proper test vector values")

	key, err = decodeOSstring("91 28 13 29 2E 3D 36 FE 3B FC 62 F1 DC 51 C3 AC")
	require.NoError(t, err, "hex decode key")

	require.NoError(t, r.setupKey(key), "setupKey should not error with a valid key")
	require.Equal(t, "3D2DF3C83EF627A1E97FC38487E2519C", encodeOSstring(r.keyStream()), "keyStream should return the proper test vector values")
	require.Equal(t, "F576CD61F4405B8896BF53AA8554FC19", encodeOSstring(r.keyStream()), "keyStream should return the proper test vector values")
	require.Equal(t, "E5547473FBDB43508AE53B20204D4C5E", encodeOSstring(r.keyStream()), "keyStream should return the proper test vector values")

	key, err = decodeOSstring("83 95 74 15 87 E0 C7 33 E9 E9 AB 01 C0 9B 00 43")
	require.NoError(t, err, "hex decode key")

	require.NoError(t, r.setupKey(key), "setupKey should not error with a valid key")
	require.Equal(t, "0CB10DCDA041CDAC32EB5CFD02D0609B", encodeOSstring(r.keyStream()), "keyStream should return the proper test vector values")
	require.Equal(t, "95FC9FCA0F17015A7B7092114CFF3EAD", encodeOSstring(r.keyStream()), "keyStream should return the proper test vector values")
	require.Equal(t, "9649E5DE8BFC7F3F924147AD3A947428", encodeOSstring(r.keyStream()), "keyStream should return the proper test vector values")
}

func decodeOSstring(str string) ([]byte, error) {
	b, err := hex.DecodeString(strings.Replace(str, " ", "", -1))
	if err == nil {
		reverse(b)
	}

	return b, err
}

func encodeOSstring(b []byte) string {
	b2 := make([]byte, len(b))
	copy(b2, b)
	reverse(b2)
	return strings.ToUpper(hex.EncodeToString(b2))
}

func reverse(a []byte) {
	for left, right := 0, len(a)-1; left < right; left, right = left+1, right-1 {
		a[left], a[right] = a[right], a[left]
	}
}
