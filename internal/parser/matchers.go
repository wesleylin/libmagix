package parser

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// Handler is a function type for matching rules against data
type Handler func(data []byte, r *Rule, offset int64) (bool, int64)

// matchString matches string rules against data
func matchString(data []byte, r *Rule, offset int64) (bool, int64) {
	valStr, ok := r.Value.(string)
	if !ok {
		return false, 0
	}
	if offset < 0 || offset >= int64(len(data)) {
		return false, 0
	}
	if bytes.HasPrefix(data[offset:], []byte(valStr)) {
		return true, offset
	}
	return false, 0
}

// matchPString matches Pascal string rules against data
func matchPString(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 || offset >= int64(len(data)) {
		return false, 0
	}

	var strLen int64
	var headerLen int64

	switch r.PStringLengthType {
	case "B": // 1-byte length
		strLen = int64(data[offset])
		headerLen = 1
	case "h": // 2-byte little-endian
		if offset+2 > int64(len(data)) {
			return false, 0
		}
		strLen = int64(binary.LittleEndian.Uint16(data[offset : offset+2]))
		headerLen = 2
	case "H": // 2-byte big-endian
		if offset+2 > int64(len(data)) {
			return false, 0
		}
		strLen = int64(binary.BigEndian.Uint16(data[offset : offset+2]))
		headerLen = 2
	case "l": // 4-byte little-endian
		if offset+4 > int64(len(data)) {
			return false, 0
		}
		strLen = int64(binary.LittleEndian.Uint32(data[offset : offset+4]))
		headerLen = 4
	case "L": // 4-byte big-endian
		if offset+4 > int64(len(data)) {
			return false, 0
		}
		strLen = int64(binary.BigEndian.Uint32(data[offset : offset+4]))
		headerLen = 4
	default:
		strLen = int64(data[offset])
		headerLen = 1
	}

	dataStart := offset + headerLen
	if dataStart+strLen > int64(len(data)) {
		return false, 0
	}

	actualStr := data[dataStart : dataStart+strLen]
	expectedVal, ok := r.Value.(string)
	if !ok {
		return true, dataStart + strLen
	}

	if strings.Contains(string(actualStr), expectedVal) {
		return true, dataStart + strLen
	}

	return false, 0
}

// matchUTF16LE matches UTF-16 little-endian string rules against data
func matchUTF16LE(data []byte, r *Rule, offset int64) (bool, int64) {
	expectedVal, ok := r.Value.(string)
	if !ok {
		return false, 0
	}

	if offset < 0 || offset+2 > int64(len(data)) {
		return false, 0
	}

	utf16Buf := make([]uint16, len(expectedVal))
	for i, runeVal := range expectedVal {
		utf16Buf[i] = uint16(runeVal)
	}

	pattern := make([]byte, len(utf16Buf)*2)
	for i, u := range utf16Buf {
		binary.LittleEndian.PutUint16(pattern[i*2:], u)
	}

	idx := bytes.Index(data[offset:], pattern)
	if idx == -1 {
		return false, 0
	}

	return true, offset + int64(idx) + int64(len(pattern))
}

// matchUTF16BE matches UTF-16 big-endian string rules against data
func matchUTF16BE(data []byte, r *Rule, offset int64) (bool, int64) {
	expectedVal, ok := r.Value.(string)
	if !ok {
		return false, 0
	}

	if offset < 0 || offset+2 > int64(len(data)) {
		return false, 0
	}

	utf16Buf := make([]uint16, len(expectedVal))
	for i, runeVal := range expectedVal {
		utf16Buf[i] = uint16(runeVal)
	}

	pattern := make([]byte, len(utf16Buf)*2)
	for i, u := range utf16Buf {
		binary.BigEndian.PutUint16(pattern[i*2:], u)
	}

	idx := bytes.Index(data[offset:], pattern)
	if idx == -1 {
		return false, 0
	}

	return true, offset + int64(idx) + int64(len(pattern))
}

// matchSearch matches search rules against data within a range.
// Important: If it finds a match at byte 500 relative to offset, it returns true, 500.
func matchSearch(data []byte, r *Rule, offset int64) (bool, int64) {
	valStr, ok := r.Value.(string)
	if !ok {
		return false, 0
	}
	pattern := []byte(valStr)
	if offset < 0 || offset >= int64(len(data)) {
		return false, 0
	}

	searchEnd := offset + r.SearchRange
	if searchEnd > int64(len(data)) {
		searchEnd = int64(len(data))
	}

	idx := bytes.Index(data[offset:searchEnd], pattern)
	if idx == -1 {
		return false, 0
	}
	// Return the absolute offset where match was found (offset + relative index)
	return true, offset + int64(idx)
}

// matchByte matches byte rules against data
func matchByte(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 || offset >= int64(len(data)) {
		return false, 0
	}

	actual := uint64(data[offset])
	if r.HasMask {
		actual = actual & r.Mask
	}

	expected := castToUint64(r.Value)
	return compare(actual, expected, r.Operator), offset
}

// matchShortLE matches little-endian short (2 bytes) rules against data
func matchShortLE(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset+2 > int64(len(data)) {
		return false, 0
	}
	actual := uint64(binary.LittleEndian.Uint16(data[offset : offset+2]))
	if r.HasMask {
		actual = actual & r.Mask
	}
	expected := castToUint64(r.Value)
	return compare(actual, expected, r.Operator), offset
}

// matchShortBE matches big-endian short (2 bytes) rules against data
func matchShortBE(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset+2 > int64(len(data)) {
		return false, 0
	}
	actual := uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
	if r.HasMask {
		actual = actual & r.Mask
	}
	expected := castToUint64(r.Value)
	return compare(actual, expected, r.Operator), offset
}

// matchLongLE matches little-endian long (4 bytes) rules against data
func matchLongLE(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset+4 > int64(len(data)) {
		return false, 0
	}
	actual := uint64(binary.LittleEndian.Uint32(data[offset : offset+4]))
	if r.HasMask {
		actual = actual & r.Mask
	}
	expected := castToUint64(r.Value)
	return compare(actual, expected, r.Operator), offset
}

// matchLongBE matches big-endian long (4 bytes) rules against data
func matchLongBE(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset+4 > int64(len(data)) {
		return false, 0
	}
	actual := uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
	if r.HasMask {
		actual = actual & r.Mask
	}
	expected := castToUint64(r.Value)
	return compare(actual, expected, r.Operator), offset
}

// matchNumericHandler is a fallback handler for unknown types that defaults to numeric matching
func matchNumericHandler(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 || offset >= int64(len(data)) {
		return false, 0
	}

	var actual uint64
	switch r.Type {
	case "belong", "ubelong", "uint32", "long": // Big Endian 4 bytes
		if offset+4 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
	case "lelong", "ulelong": // Little Endian 4 bytes
		if offset+4 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.LittleEndian.Uint32(data[offset : offset+4]))
	case "short", "beshort", "ubeshort": // Big Endian 2 bytes
		if offset+2 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
	case "leshort", "uleshort", "uint16": // Little Endian 2 bytes
		if offset+2 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.LittleEndian.Uint16(data[offset : offset+2]))
	case "byte", "ubyte": // 1 byte
		actual = uint64(data[offset])
	default:
		return false, 0
	}

	if r.HasMask {
		actual = actual & r.Mask
	}

	expected := castToUint64(r.Value)
	return compare(actual, expected, r.Operator), offset
}

// compare handles the operators: =, !, >, <, &, ^
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
		return (actual & expected) == expected
	case "^":
		return (actual & expected) == 0
	default:
		return actual == expected
	}
}

// castToUint64 safely converts r.Value (uint8, uint16, uint32, uint64, int) to uint64
func castToUint64(v any) uint64 {
	switch val := v.(type) {
	case uint64:
		return val // Already a uint64, no cast needed!
	case uint32:
		return uint64(val)
	case uint16:
		return uint64(val)
	case uint8:
		return uint64(val)
	case int:
		return uint64(val)
	case int32:
		return uint64(val)
	case int64:
		return uint64(val)
	default:
		return 0
	}
}
