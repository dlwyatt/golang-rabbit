package rabbit

import (
	"errors"
	"math/bits"
)

var a = [8]uint32{0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3}

type Rabbit interface {
	encrypt(message []byte) (cipher []byte, err error)
	setupIV(iv []byte) error
	setupKey(key []byte) error
	reset()
}

type rabbit struct {
	x       [8]uint32
	masterX [8]uint32
	c       [8]uint32
	masterC [8]uint32
	b       byte
	masterB byte

	keySetupCalled bool
}

func New() Rabbit {
	return newRabbit()
}

func newRabbit() *rabbit {
	return &rabbit{}
}

func (r *rabbit) encrypt(message []byte) (cipher []byte, err error) {
	return
}

func (r *rabbit) setupIV(iv []byte) error {
	if !r.keySetupCalled {
		return errors.New("setupKey must be called before setupIV")
	}

	if len(iv) != 8 {
		return errors.New("iv must be 8 bytes")
	}

	copy(r.x[0:8], r.masterX[0:8])
	copy(r.c[0:8], r.masterC[0:8])
	r.b = r.masterB

	var siv [4]uint16
	for i := 0; i < 4; i++ {
		siv[i] = (uint16(iv[2*i+1]) << 8) | uint16(iv[2*i])
	}

	r.c[0] ^= (uint32(siv[1]) << 16) | uint32(siv[0])
	r.c[1] ^= (uint32(siv[3]) << 16) | uint32(siv[1])
	r.c[2] ^= (uint32(siv[3]) << 16) | uint32(siv[2])
	r.c[3] ^= (uint32(siv[2]) << 16) | uint32(siv[0])
	r.c[4] ^= (uint32(siv[1]) << 16) | uint32(siv[0])
	r.c[5] ^= (uint32(siv[3]) << 16) | uint32(siv[1])
	r.c[6] ^= (uint32(siv[3]) << 16) | uint32(siv[2])
	r.c[7] ^= (uint32(siv[2]) << 16) | uint32(siv[0])

	r.nextState()
	r.nextState()
	r.nextState()
	r.nextState()

	return nil
}

func (r *rabbit) setupKey(key []byte) error {
	if len(key) != 16 {
		return errors.New("key must be 16 bytes")
	}

	r.reset()
	r.keySetupCalled = true

	var k [8]uint16
	for i := 0; i < 8; i++ {
		k[i] = (uint16(key[2*i+1]) << 8) | uint16(key[2*i])
	}

	r.x[0] = (uint32(k[1]) << 16) | uint32(k[0])
	r.x[1] = (uint32(k[6]) << 16) | uint32(k[5])
	r.x[2] = (uint32(k[3]) << 16) | uint32(k[2])
	r.x[3] = (uint32(k[0]) << 16) | uint32(k[7])
	r.x[4] = (uint32(k[5]) << 16) | uint32(k[4])
	r.x[5] = (uint32(k[2]) << 16) | uint32(k[1])
	r.x[6] = (uint32(k[7]) << 16) | uint32(k[6])
	r.x[7] = (uint32(k[4]) << 16) | uint32(k[3])

	r.c[0] = (uint32(k[4]) << 16) | uint32(k[5])
	r.c[1] = (uint32(k[1]) << 16) | uint32(k[2])
	r.c[2] = (uint32(k[6]) << 16) | uint32(k[7])
	r.c[3] = (uint32(k[3]) << 16) | uint32(k[4])
	r.c[4] = (uint32(k[0]) << 16) | uint32(k[1])
	r.c[5] = (uint32(k[5]) << 16) | uint32(k[6])
	r.c[6] = (uint32(k[2]) << 16) | uint32(k[3])
	r.c[7] = (uint32(k[7]) << 16) | uint32(k[0])

	r.nextState()
	r.nextState()
	r.nextState()
	r.nextState()

	r.c[0] ^= r.x[4]
	r.c[1] ^= r.x[5]
	r.c[2] ^= r.x[6]
	r.c[3] ^= r.x[7]
	r.c[4] ^= r.x[0]
	r.c[5] ^= r.x[1]
	r.c[6] ^= r.x[2]
	r.c[7] ^= r.x[3]

	copy(r.masterX[0:8], r.x[0:8])
	copy(r.masterC[0:8], r.c[0:8])
	r.masterB = r.b

	return nil
}

func (r *rabbit) reset() {
	for i := 0; i < 8; i++ {
		r.x[i] = 0
		r.c[i] = 0
		r.masterX[i] = 0
		r.masterC[i] = 0
	}

	r.b = 0
	r.masterB = 0
	r.keySetupCalled = false

	return
}

func gfunc(x uint32) uint32 {
	a := x & 0xFFFF
	b := x >> 16
	h := (((uint32(a*a) >> 17) + uint32(a*b)) >> 15) + b*b
	l := x * x

	return uint32(h ^ l)
}

func (r *rabbit) nextState() {
	var t uint64
	for i := 0; i < 8; i++ {
		t = uint64(r.c[i]) + uint64(a[i]) + uint64(r.b)
		r.b = 0
		if byte(t>>32) > 0 {
			r.b = 1
		}

		r.c[i] = uint32(t & 0xFFFFFFFF)
	}

	var g [8]uint32
	for i := 0; i < 8; i++ {
		t = (uint64(r.x[i]) + uint64(r.c[i])) & 0xFFFFFFFF
		t *= t
		g[i] = uint32(t&0xFFFFFFFF) ^ uint32((t>>32)&0xFFFFFFFF)
	}

	r.x[0] = uint32((uint64(g[0]) + uint64(bits.RotateLeft32(g[7], 16)) + uint64(bits.RotateLeft32(g[6], 16))) & 0xFFFFFFFF)
	r.x[1] = uint32((uint64(g[1]) + uint64(bits.RotateLeft32(g[0], 8)) + uint64(g[7])) & 0xFFFFFFFF)
	r.x[2] = uint32((uint64(g[2]) + uint64(bits.RotateLeft32(g[1], 16)) + uint64(bits.RotateLeft32(g[0], 16))) & 0xFFFFFFFF)
	r.x[3] = uint32((uint64(g[3]) + uint64(bits.RotateLeft32(g[2], 8)) + uint64(g[1])) & 0xFFFFFFFF)
	r.x[4] = uint32((uint64(g[4]) + uint64(bits.RotateLeft32(g[3], 16)) + uint64(bits.RotateLeft32(g[2], 16))) & 0xFFFFFFFF)
	r.x[5] = uint32((uint64(g[5]) + uint64(bits.RotateLeft32(g[4], 8)) + uint64(g[3])) & 0xFFFFFFFF)
	r.x[6] = uint32((uint64(g[6]) + uint64(bits.RotateLeft32(g[5], 16)) + uint64(bits.RotateLeft32(g[4], 16))) & 0xFFFFFFFF)
	r.x[7] = uint32((uint64(g[7]) + uint64(bits.RotateLeft32(g[6], 8)) + uint64(g[5])) & 0xFFFFFFFF)
}

func (r *rabbit) keyStream() []byte {
	r.nextState()
	var s = make([]byte, 16)
	var x uint16

	x = uint16(r.x[0]&0xFFFF) ^ uint16(r.x[5]>>16)
	s[0] = byte(x & 0xFF)
	s[1] = byte(x >> 8)

	x = uint16(r.x[3]&0xFFFF) ^ uint16(r.x[0]>>16)
	s[2] = byte(x & 0xFF)
	s[3] = byte(x >> 8)

	x = uint16(r.x[2]&0xFFFF) ^ uint16(r.x[7]>>16)
	s[4] = byte(x & 0xFF)
	s[5] = byte(x >> 8)

	x = uint16(r.x[5]&0xFFFF) ^ uint16(r.x[2]>>16)
	s[6] = byte(x & 0xFF)
	s[7] = byte(x >> 8)

	x = uint16(r.x[4]&0xFFFF) ^ uint16(r.x[1]>>16)
	s[8] = byte(x & 0xFF)
	s[9] = byte(x >> 8)

	x = uint16(r.x[7]&0xFFFF) ^ uint16(r.x[4]>>16)
	s[10] = byte(x & 0xFF)
	s[11] = byte(x >> 8)

	x = uint16(r.x[6]&0xFFFF) ^ uint16(r.x[3]>>16)
	s[12] = byte(x & 0xFF)
	s[13] = byte(x >> 8)

	x = uint16(r.x[1]&0xFFFF) ^ uint16(r.x[6]>>16)
	s[14] = byte(x & 0xFF)
	s[15] = byte(x >> 8)

	return s
}
