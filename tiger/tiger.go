// Copyright (c) 2013 Yoran Heling
// TODO: use cgo. This implementation one really isn't fast enough
package tiger

import "hash"

const BlockSize = 64
const Size = 24

type digest struct {
	hash   [3]uint64
	buf    [BlockSize / 8]uint64
	length uint64
}

func New() hash.Hash {
	d := &digest{}
	d.Reset()
	return d
}

func (d *digest) Size() int {
	return Size
}

func (d *digest) BlockSize() int {
	return BlockSize
}

func (d *digest) Sum(b []byte) []byte {
	// Copy digest to write the suffix to the data
	d0 := new(digest)
	*d0 = *d
	d = d0

	// Append 0x01 and the total length of the message
	// (not the fastest code)
	length := d.length << 3
	d.Write([]byte{1})
	idx := d.length % BlockSize
	if idx > 56 {
		for i := 56 + (64 - idx); i > 0; i-- {
			d.Write([]byte{0})
		}
	} else {
		for ; idx < 56; idx++ {
			d.Write([]byte{0})
		}
	}
	d.Write([]byte{byte(length), byte(length >> 8), byte(length >> 16), byte(length >> 24), byte(length >> 32), byte(length >> 40), byte(length >> 48), byte(length >> 56)})

	var p [Size]byte
	// Bytes are written back in little-endian order, for some reason
	for i, s := range d.hash {
		p[i*8+0] = byte(s >> 0)
		p[i*8+1] = byte(s >> 8)
		p[i*8+2] = byte(s >> 16)
		p[i*8+3] = byte(s >> 24)
		p[i*8+4] = byte(s >> 32)
		p[i*8+5] = byte(s >> 40)
		p[i*8+6] = byte(s >> 48)
		p[i*8+7] = byte(s >> 56)
	}
	return append(b, p[:]...)
}

func (d *digest) Reset() {
	d.length = 0
	d.hash[0] = 0x0123456789ABCDEF
	d.hash[1] = 0xFEDCBA9876543210
	d.hash[2] = 0xF096A5B4C3B2E187
}

func (d *digest) Write(p []byte) (n int, err error) {
	// Write to buf and call process_block() when it's full
	for i := 0; i < len(p); {
		n := (d.length / 8) & 7
		r := d.length & 7
		// If we're writing a new 64bit value and the input is at least 8 bytes, do it the fast way
		if r == 0 && len(p)-i >= 8 {
			d.buf[n] = uint64(p[i]) + uint64(p[i+1])<<8 + uint64(p[i+2])<<16 + uint64(p[i+3])<<24 + uint64(p[i+4])<<32 + uint64(p[i+5])<<40 + uint64(p[i+6])<<48 + uint64(p[i+7])<<56
			d.length += 8
			i += 8
			// Otherwise, the slow way
		} else {
			if r == 0 {
				d.buf[n] = 0
			}
			d.buf[n] += uint64(p[i]) << (uint(r) * 8)
			d.length += 1
			i++
		}
		// If we have a full buffer, call process_block
		if d.length%BlockSize == 0 {
			d.process_block()
		}
	}
	return len(p), nil
}

func (d *digest) process_block() {
	a := d.hash[0]
	b := d.hash[1]
	c := d.hash[2]

	sl := d.buf[:]
	pass(&a, &b, &c, sl, 5)
	schedule(sl)
	pass(&c, &a, &b, sl, 7)
	schedule(sl)
	pass(&b, &c, &a, sl, 9)

	d.hash[0] = a ^ d.hash[0]
	d.hash[1] = b - d.hash[1]
	d.hash[2] = c + d.hash[2]
}

func round(a, b, c *uint64, x, mul uint64) {
	*c ^= x
	*a -= sb1[uint8(*c)] ^ sb2[uint8(*c>>16)] ^ sb3[uint8(*c>>32)] ^ sb4[uint8(*c>>48)]
	*b += sb4[uint8(*c>>8)] ^ sb3[uint8(*c>>24)] ^ sb2[uint8(*c>>40)] ^ sb1[uint8(*c>>56)]
	*b *= mul
}

func pass(a, b, c *uint64, x []uint64, mul uint64) {
	round(a, b, c, x[0], mul)
	round(b, c, a, x[1], mul)
	round(c, a, b, x[2], mul)
	round(a, b, c, x[3], mul)
	round(b, c, a, x[4], mul)
	round(c, a, b, x[5], mul)
	round(a, b, c, x[6], mul)
	round(b, c, a, x[7], mul)
}

func schedule(x []uint64) {
	x[0] -= x[7] ^ 0xA5A5A5A5A5A5A5A5
	x[1] ^= x[0]
	x[2] += x[1]
	x[3] -= x[2] ^ ((^x[1]) << 19)
	x[4] ^= x[3]
	x[5] += x[4]
	x[6] -= x[5] ^ ((^x[4]) >> 23)
	x[7] ^= x[6]
	x[0] += x[7]
	x[1] -= x[0] ^ ((^x[7]) << 19)
	x[2] ^= x[1]
	x[3] += x[2]
	x[4] -= x[3] ^ ((^x[2]) >> 23)
	x[5] ^= x[4]
	x[6] += x[5]
	x[7] -= x[6] ^ 0x0123456789ABCDEF
}
