package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// Rule represents a single line in a magic file
type Rule struct {
	Level    int
	Offset   int64
	Type     string
	Operator string
	Mask     uint64
	HasMask  bool
	Value    any
	ValueRaw []byte
	Message  string
	Mime     string
	MatchAny bool // Support for 'x' value in magic files

	// Indirect Offset support: (offset.type[+-/*]value)
	IsIndirect    bool
	PointerOffset int64
	PointerType   string
	PointerAdd    int64

	SearchRange int64
	IsRelative  bool // Support for '&' relative offset

	Children []Rule
}

func (r Rule) String() string {
	indent := strings.Repeat("> ", r.Level)
	typeDisplay := r.Type
	if r.HasMask {
		typeDisplay = fmt.Sprintf("%s&0x%X", r.Type, r.Mask)
	}
	return fmt.Sprintf("%-10s L%d Off:%-5d %-15s %s %v -> %s",
		indent, r.Level, r.Offset, typeDisplay, r.Operator, r.Value, r.Message)
}

// Match checks if this rule matches the provided data.
// It takes a baseOffset (the match location of the parent rule) to support relative offsets.
// It returns whether it matched and the absolute offset where the match occurred.
func (r *Rule) Match(data []byte, baseOffset int64) (bool, int64) {
	// 0. Handle Relative Offset
	absoluteOffset := r.Offset
	if r.IsRelative {
		absoluteOffset += baseOffset
	}

	// 1. Resolve Offset (Handling Indirect Offsets)
	actualOffset := absoluteOffset
	if r.IsIndirect {
		// Indirect offsets themselves can be relative: (&0.l)
		ptrOff := r.PointerOffset
		if r.IsRelative {
			ptrOff += baseOffset
		}

		if ptrOff < 0 || ptrOff >= int64(len(data)) {
			return false, 0
		}

		var pointerVal int64
		switch r.PointerType {
		case "b": // byte
			pointerVal = int64(data[ptrOff])
		case "s": // little-endian short
			if ptrOff+2 > int64(len(data)) {
				return false, 0
			}
			pointerVal = int64(binary.LittleEndian.Uint16(data[ptrOff : ptrOff+2]))
		case "S": // big-endian short
			if ptrOff+2 > int64(len(data)) {
				return false, 0
			}
			pointerVal = int64(binary.BigEndian.Uint16(data[ptrOff : ptrOff+2]))
		case "l": // little-endian long
			if ptrOff+4 > int64(len(data)) {
				return false, 0
			}
			pointerVal = int64(binary.LittleEndian.Uint32(data[ptrOff : ptrOff+4]))
		case "L": // big-endian long
			if ptrOff+4 > int64(len(data)) {
				return false, 0
			}
			pointerVal = int64(binary.BigEndian.Uint32(data[ptrOff : ptrOff+4]))
		}
		actualOffset = pointerVal + r.PointerAdd
	}

	// 2. Handle Search Type
	if r.Type == "search" {
		valStr, ok := r.Value.(string)
		if !ok {
			return false, 0
		}
		pattern := []byte(valStr)
		if actualOffset < 0 || actualOffset >= int64(len(data)) {
			return false, 0
		}

		searchEnd := actualOffset + r.SearchRange
		if searchEnd > int64(len(data)) {
			searchEnd = int64(len(data))
		}

		idx := bytes.Index(data[actualOffset:searchEnd], pattern)
		if idx == -1 {
			return false, 0
		}
		return true, actualOffset + int64(idx)
	}

	// 3. Bounds check
	if actualOffset < 0 || actualOffset >= int64(len(data)) {
		return false, 0
	}

	// 1.1 MatchAny 'x' (always matches if within bounds)
	if r.MatchAny {
		return true, actualOffset
	}

	// 4. Handle Strings
	if r.Type == "string" {
		valStr, ok := r.Value.(string)
		if !ok {
			return false, 0
		}
		if bytes.HasPrefix(data[actualOffset:], []byte(valStr)) {
			return true, actualOffset
		}
		return false, 0
	}

	// 5. Handle Numeric Types
	var actual uint64
	switch r.Type {
	case "belong", "ubelong", "uint32", "long": // Big Endian 4 bytes
		if actualOffset+4 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.BigEndian.Uint32(data[actualOffset : actualOffset+4]))
	case "lelong", "ulelong": // Little Endian 4 bytes
		if actualOffset+4 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.LittleEndian.Uint32(data[actualOffset : actualOffset+4]))
	case "short", "beshort", "ubeshort": // Big Endian 2 bytes
		if actualOffset+2 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.BigEndian.Uint16(data[actualOffset : actualOffset+2]))
	case "leshort", "uleshort", "uint16": // Little Endian 2 bytes
		if actualOffset+2 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.LittleEndian.Uint16(data[actualOffset : actualOffset+2]))
	case "byte", "ubyte": // 1 byte
		actual = uint64(data[actualOffset])
	default:
		return false, 0
	}

	if r.HasMask {
		actual = actual & r.Mask
	}

	expected := castToUint64(r.Value)
	if compare(actual, expected, r.Operator) {
		return true, actualOffset
	}
	return false, 0
}

// compare handles the operators: =, !, >, <, &
func compare(actual, expected uint64, op string) bool {
	switch op {
	case "=":
		return actual == expected
	case "!":
		return actual != expected
	case ">":
		return actual > expected
	case "<":
		return actual < expected
	case "&":
		// This operator means "are all these bits set?"
		return (actual & expected) == expected
	case "^":
		// This operator means "is this bit NOT set?"
		return (actual & expected) == 0
	default:
		// Default to equality if unknown
		return actual == expected
	}
}

// castToUint64 safely converts our generic r.Value (uint8, uint16, uint32) to uint64
func castToUint64(v any) uint64 {
	switch t := v.(type) {
	case uint32:
		return uint64(t)
	case uint16:
		return uint64(t)
	case uint8:
		return uint64(t)
	case int: // Sometimes ParseInt might leave it as int
		return uint64(t)
	default:
		return 0
	}
}

func (r *Rule) MatchByte(data []byte) bool {
	val := r.ValueRaw

	end := int(r.Offset) + len(val)
	if r.Offset < 0 || len(data) < end {
		return false
	}

	return bytes.Equal(data[r.Offset:end], val)
}
