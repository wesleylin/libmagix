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
	// Empty string matches at the current offset (must be within bounds)
	if valStr == "" {
		return true, offset
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

	var strLen int
	var headerLen int64

	switch r.PStringLengthType {
	case "B": // 1-byte length
		strLen = int(data[offset])
		headerLen = 1
	case "h": // 2-byte little-endian: low byte first, then high byte
		if offset+2 > int64(len(data)) {
			return false, 0
		}
		// First byte is low-order, second byte is high-order
		strLen = int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		headerLen = 2
	case "H": // 2-byte big-endian: high byte first, then low byte
		if offset+2 > int64(len(data)) {
			return false, 0
		}
		strLen = int(binary.BigEndian.Uint16(data[offset : offset+2]))
		headerLen = 2
	case "l": // 4-byte little-endian
		if offset+4 > int64(len(data)) {
			return false, 0
		}
		// bytes[0] is LSB, bytes[3] is MSB
		strLen = int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		headerLen = 4
	case "L": // 4-byte big-endian
		if offset+4 > int64(len(data)) {
			return false, 0
		}
		strLen = int(binary.BigEndian.Uint32(data[offset : offset+4]))
		headerLen = 4
	default:
		// Default to 1-byte length
		strLen = int(data[offset])
		headerLen = 1
	}

	dataStart := offset + int64(headerLen)
	if dataStart > int64(len(data)) {
		return false, 0
	}

	maxRead := len(data) - int(dataStart)
	if strLen > maxRead {
		strLen = maxRead
	}

	actualStr := data[dataStart : dataStart+int64(strLen)]
	expectedVal, ok := r.Value.(string)
	if !ok {
		// Invalid type - still return match but skip comparison
		return true, dataStart + int64(strLen)
	}

	// Empty string matches anywhere in the available data
	if expectedVal == "" && len(actualStr) >= 0 {
		return true, dataStart
	}

	if strings.Contains(string(actualStr), expectedVal) {
		return true, dataStart + int64(strLen)
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

	// Empty pattern matches at the offset after minimum UTF-16 header (2 bytes)
	if expectedVal == "" {
		return true, offset + 2
	}

	patternLen := len(expectedVal) * 2
	if int64(patternLen)+offset > int64(len(data)) {
		return false, 0
	}

	utf16Buf := make([]uint16, patternLen/2)
	for i := 0; i < len(expectedVal); i++ {
		utf16Buf[i] = uint16(rune(expectedVal[i]))
	}

	pattern := make([]byte, patternLen)
	for i := 0; i < len(utf16Buf); i++ {
		binary.LittleEndian.PutUint16(pattern[i*2:], utf16Buf[i])
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
	if offset < 0 || offset > int64(len(data)) {
		return false, 0
	}

	pattern := []byte(valStr)
	maxSearchEnd := int64(len(data))

	if r.SearchRange > 0 && offset+r.SearchRange < maxSearchEnd {
		maxSearchEnd = offset + r.SearchRange
	}

	if offset > maxSearchEnd {
		return false, 0
	}

	idx := bytes.Index(data[offset:maxSearchEnd], pattern)
	if idx == -1 {
		return false, 0
	}
	return true, offset + int64(idx)
}

// matchByte matches byte rules against data
func matchByte(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 || offset >= int64(len(data)) {
		return false, 0
	}
	actual := uint64(data[offset])
	expected := castToUint64(r.Value)
	if r.HasMask {
		actual &= r.Mask
		expected &= r.Mask
	}
	return compare(actual, expected, r.Operator), offset + 1
}

// matchShortLE matches little-endian short (2 bytes) rules against data
func matchShortLE(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 {
		return false, 0
	}
	if offset+2 > int64(len(data)) {
		return false, 0
	}
	actual := uint64(binary.LittleEndian.Uint16(data[offset : offset+2]))
	expected := castToUint64(r.Value)

	if r.HasMask {
		// Apply mask to both actual and expected for consistent comparison
		maskedActual := actual & r.Mask
		maskedExpected := expected & r.Mask
		return compare(maskedActual, maskedExpected, r.Operator), offset
	}

	return compare(actual, expected, r.Operator), offset
}

// matchShortBE matches big-endian short (2 bytes) rules against data
func matchShortBE(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 {
		return false, 0
	}
	if offset+2 > int64(len(data)) {
		return false, 0
	}
	actual := uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
	expected := castToUint64(r.Value)

	if r.HasMask {
		// Apply mask to both actual and expected for consistent comparison
		maskedActual := actual & r.Mask
		maskedExpected := expected & r.Mask
		return compare(maskedActual, maskedExpected, r.Operator), offset
	}

	return compare(actual, expected, r.Operator), offset
}

// matchLongLE matches little-endian long (4 bytes) rules against data
func matchLongLE(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 {
		return false, 0
	}
	if offset+4 > int64(len(data)) {
		return false, 0
	}
	actual := uint64(binary.LittleEndian.Uint32(data[offset : offset+4]))
	expected := castToUint64(r.Value)

	if r.HasMask {
		// Apply mask to both actual and expected for consistent comparison
		maskedActual := actual & r.Mask
		maskedExpected := expected & r.Mask
		return compare(maskedActual, maskedExpected, r.Operator), offset
	}

	return compare(actual, expected, r.Operator), offset
}

// matchLongBE matches big-endian long (4 bytes) rules against data
func matchLongBE(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 {
		return false, 0
	}
	if offset+4 > int64(len(data)) {
		return false, 0
	}
	actual := uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
	expected := castToUint64(r.Value)

	if r.HasMask {
		// Apply mask to both actual and expected for consistent comparison
		maskedActual := actual & r.Mask
		maskedExpected := expected & r.Mask
		return compare(maskedActual, maskedExpected, r.Operator), offset
	}

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
		return (actual & expected) != expected
	default:
		return actual == expected
	}
}

// castToUint64 safely converts r.Value (uint8, uint16, uint32, uint64, int, int32, int64) to uint64
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
		return uint64(val) // Zero-extend the entire value to 64 bits
	case int32:
		return uint64(val) // Truncate/zero-extend to 64 bits
	case int64:
		return uint64(val) // Zero-extend the entire value to 64 bits
	default:
		return 0
	}
}
