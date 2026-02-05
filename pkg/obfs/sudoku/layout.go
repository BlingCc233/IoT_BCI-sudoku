package sudoku

import (
	"fmt"
	"math/bits"
	"sort"
	"strings"
)

type byteLayout struct {
	name        string
	isASCII     bool
	hintMask    byte
	hintValue   byte
	padMarker   byte
	paddingPool []byte

	hintOK [256]bool

	encodeHint  func(value2b, pos4b byte) byte
	encodeGroup func(group6b byte) byte
	decodeGroup func(b byte) (byte, bool)
}

func (l *byteLayout) isHint(b byte) bool {
	return l.hintOK[b]
}

func resolveLayout(mode string, customPattern string) (*byteLayout, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "ascii", "prefer_ascii":
		return newASCIILayout(), nil
	case "", "entropy", "prefer_entropy":
		// fallthrough
	default:
		return nil, fmt.Errorf("invalid ascii mode: %s", mode)
	}

	if strings.TrimSpace(customPattern) != "" {
		return newCustomLayout(customPattern)
	}
	return newEntropyLayout(), nil
}

func newASCIILayout() *byteLayout {
	padding := make([]byte, 0, 32)
	for i := 0; i < 32; i++ {
		padding = append(padding, byte(0x20+i))
	}
	l := &byteLayout{
		name:        "ascii",
		isASCII:     true,
		hintMask:    0x40,
		hintValue:   0x40,
		padMarker:   0x3F,
		paddingPool: padding,
		encodeHint: func(value2b, pos4b byte) byte {
			return 0x40 | ((value2b & 0x03) << 4) | (pos4b & 0x0F)
		},
		encodeGroup: func(group6b byte) byte {
			return 0x40 | (group6b & 0x3F)
		},
		decodeGroup: func(b byte) (byte, bool) {
			if b == '\n' {
				return 0x3F, true
			}
			if (b & 0x40) == 0 {
				return 0, false
			}
			return b & 0x3F, true
		},
	}
	for i := 0; i < 256; i++ {
		b := byte(i)
		l.hintOK[b] = (b & l.hintMask) == l.hintValue
	}
	// In prefer_ascii mode we also accept '\n' as an on-wire alias for 0x7F.
	l.hintOK['\n'] = true
	return l
}

func newEntropyLayout() *byteLayout {
	padding := make([]byte, 0, 16)
	for i := 0; i < 8; i++ {
		padding = append(padding, byte(0x80+i))
		padding = append(padding, byte(0x10+i))
	}
	l := &byteLayout{
		name:        "entropy",
		isASCII:     false,
		hintMask:    0x90,
		hintValue:   0x00,
		padMarker:   0x80,
		paddingPool: padding,
		encodeHint: func(value2b, pos4b byte) byte {
			return ((value2b & 0x03) << 5) | (pos4b & 0x0F)
		},
		encodeGroup: func(group6b byte) byte {
			v := group6b & 0x3F
			return ((v & 0x30) << 1) | (v & 0x0F)
		},
		decodeGroup: func(b byte) (byte, bool) {
			if (b & 0x90) != 0 {
				return 0, false
			}
			return ((b >> 1) & 0x30) | (b & 0x0F), true
		},
	}
	for i := 0; i < 256; i++ {
		b := byte(i)
		l.hintOK[b] = (b & l.hintMask) == l.hintValue
	}
	return l
}

// newCustomLayout builds a custom bit-layout for the x/v/p appearance.
//
// Semantic correction (IoT_BCI-sudoku):
// - x: redundant bits (2 bits, always set for hint bytes)
// - p: position bits (4 bits)
// - v: value bits (2 bits)
//
// The pattern is 8 symbols mapping to bits 7..0. It must contain exactly:
// - 2 x
// - 4 p
// - 2 v
func newCustomLayout(pattern string) (*byteLayout, error) {
	cleaned := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(pattern), " ", ""))
	if len(cleaned) != 8 {
		return nil, fmt.Errorf("custom table must have 8 symbols, got %d", len(cleaned))
	}

	var xBits, pBits, vBits []uint8
	for i, c := range cleaned {
		bit := uint8(7 - i)
		switch c {
		case 'x':
			xBits = append(xBits, bit)
		case 'p':
			pBits = append(pBits, bit)
		case 'v':
			vBits = append(vBits, bit)
		default:
			return nil, fmt.Errorf("invalid char %q in custom table", c)
		}
	}
	if len(xBits) != 2 || len(pBits) != 4 || len(vBits) != 2 {
		return nil, fmt.Errorf("custom table must contain exactly 2 x, 4 p, 2 v")
	}

	xMask := byte(0)
	for _, b := range xBits {
		xMask |= 1 << b
	}

	var posBitsLUT [16]byte
	for pos := 0; pos < 16; pos++ {
		var out byte
		p := byte(pos)
		for i, bit := range pBits {
			if (p>>(3-uint8(i)))&0x01 == 1 {
				out |= 1 << bit
			}
		}
		posBitsLUT[pos] = out
	}
	var valueBitsLUT [4]byte
	for value := 0; value < 4; value++ {
		var out byte
		v := byte(value)
		if (v & 0x02) != 0 {
			out |= 1 << vBits[0]
		}
		if (v & 0x01) != 0 {
			out |= 1 << vBits[1]
		}
		valueBitsLUT[value] = out
	}

	encodeBits := func(value2b, pos4b byte, dropX int) byte {
		out := xMask | posBitsLUT[pos4b&0x0F] | valueBitsLUT[value2b&0x03]
		if dropX >= 0 {
			out &^= 1 << xBits[dropX]
		}
		return out
	}

	var encodeHintLUT [64]byte
	for value2b := 0; value2b < 4; value2b++ {
		for pos4b := 0; pos4b < 16; pos4b++ {
			encodeHintLUT[(value2b<<4)|pos4b] = encodeBits(byte(value2b), byte(pos4b), -1)
		}
	}
	var encodeGroupLUT [64]byte
	for g := 0; g < 64; g++ {
		value2b := byte((g >> 4) & 0x03)
		pos4b := byte(g & 0x0F)
		encodeGroupLUT[g] = encodeBits(value2b, pos4b, -1)
	}
	var decodeGroupLUT [256]byte
	var decodeGroupOK [256]bool
	for b := 0; b < 256; b++ {
		bb := byte(b)
		if (bb & xMask) != xMask {
			continue
		}
		var value2b, pos4b byte
		for i, bit := range pBits {
			if bb&(1<<bit) != 0 {
				pos4b |= 1 << (3 - uint8(i))
			}
		}
		if bb&(1<<vBits[0]) != 0 {
			value2b |= 0x02
		}
		if bb&(1<<vBits[1]) != 0 {
			value2b |= 0x01
		}
		group := (value2b << 4) | (pos4b & 0x0F)
		decodeGroupLUT[b] = group
		decodeGroupOK[b] = true
	}

	// Build a padding pool by dropping one redundant x-bit so padding bytes are never hints.
	paddingSet := make(map[byte]struct{})
	var padding []byte
	for drop := range xBits {
		for value2b := 0; value2b < 4; value2b++ {
			for pos4b := 0; pos4b < 16; pos4b++ {
				b := encodeBits(byte(value2b), byte(pos4b), drop)
				// Hamming weight constraint: padding looks "busy" to reduce obvious markers.
				if bits.OnesCount8(b) >= 5 {
					if _, ok := paddingSet[b]; !ok {
						paddingSet[b] = struct{}{}
						padding = append(padding, b)
					}
				}
			}
		}
	}
	sort.Slice(padding, func(i, j int) bool { return padding[i] < padding[j] })
	if len(padding) == 0 {
		return nil, fmt.Errorf("custom table produced empty padding pool")
	}

	return &byteLayout{
		name:        fmt.Sprintf("custom(%s)", cleaned),
		isASCII:     false,
		hintMask:    xMask,
		hintValue:   xMask,
		padMarker:   padding[0],
		paddingPool: padding,
		hintOK:      decodeGroupOK,
		encodeHint: func(value2b, pos4b byte) byte {
			return encodeHintLUT[((value2b&0x03)<<4)|(pos4b&0x0F)]
		},
		encodeGroup: func(group6b byte) byte {
			return encodeGroupLUT[group6b&0x3F]
		},
		decodeGroup: func(b byte) (byte, bool) {
			if !decodeGroupOK[b] {
				return 0, false
			}
			return decodeGroupLUT[b], true
		},
	}, nil
}
