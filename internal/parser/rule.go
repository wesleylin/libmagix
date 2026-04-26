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
	RuleName string // For 'name' blocks

	// Pascal String support: pstring/modifier
	PStringLengthType string // 'B', 'H', 'h', 'l', 'L'

	// Indirect Offset Adjustment: (offset.type+adj)
	PointerAdjustment int64
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
func (r *Rule) Match(data []byte, baseOffset int64, forcedRelative bool) (bool, int64) {
	// 1. Resolve the actual offset (handling relative and indirect offsets)
	actualOffset, ok := r.resolveOffset(data, baseOffset, forcedRelative)
	if !ok {
		return false, 0
	}

	// Handle Meta-types
	if r.Type == "name" {
		return false, 0 // Declarations don't match data
	}
	if r.Type == "use" {
		// 'use' calls always "match" to trigger the jump,
		// and they always use the current baseOffset.
		return true, actualOffset
	}

	// 2. MatchAny 'x' (always matches if within bounds)
	if r.MatchAny {
		if actualOffset < 0 || actualOffset >= int64(len(data)) {
			return false, 0
		}
		return true, actualOffset
	}

	// 3. Delegate to type-specific handlers
	switch r.Type {
	case "string":
		return r.matchString(data, actualOffset)
	case "pstring":
		return r.matchPString(data, actualOffset)
	case "lestring16":
		return r.matchUTF16(data, actualOffset, binary.LittleEndian)
	case "bestring16":
		return r.matchUTF16(data, actualOffset, binary.BigEndian)
	case "search":
		return r.matchSearch(data, actualOffset)
	default:
		// Numeric types
		return r.matchNumeric(data, actualOffset)
	}
}

// resolveOffset calculates the final absolute offset, handling relative (&) and indirect ((...)) syntax.
func (r *Rule) resolveOffset(data []byte, baseOffset int64, forcedRelative bool) (int64, bool) {
	// 0. Initial offset
	absoluteOffset := r.Offset
	if r.IsRelative || forcedRelative {
		absoluteOffset += baseOffset
	}

	// 1. Handle Indirect Offsets (e.g., (0x3c.l))
	actualOffset := absoluteOffset
	if r.IsIndirect {
		ptrOff := r.PointerOffset
		if r.IsRelative || forcedRelative {
			ptrOff += baseOffset
		}

		if ptrOff < 0 || ptrOff >= int64(len(data)) {
			return 0, false
		}

		var pointerVal int64
		switch r.PointerType {
		case "b": // byte
			pointerVal = int64(data[ptrOff])
		case "s": // little-endian short
			if ptrOff+2 > int64(len(data)) {
				return 0, false
			}
			pointerVal = int64(binary.LittleEndian.Uint16(data[ptrOff : ptrOff+2]))
		case "S": // big-endian short
			if ptrOff+2 > int64(len(data)) {
				return 0, false
			}
			pointerVal = int64(binary.BigEndian.Uint16(data[ptrOff : ptrOff+2]))
		case "l": // little-endian long
			if ptrOff+4 > int64(len(data)) {
				return 0, false
			}
			pointerVal = int64(binary.LittleEndian.Uint32(data[ptrOff : ptrOff+4]))
		case "L": // big-endian long
			if ptrOff+4 > int64(len(data)) {
				return 0, false
			}
			pointerVal = int64(binary.BigEndian.Uint32(data[ptrOff : ptrOff+4]))
		}
		actualOffset = pointerVal + r.PointerAdd + r.PointerAdjustment
	}

	return actualOffset, true
}

func (r *Rule) matchString(data []byte, offset int64) (bool, int64) {
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

func (r *Rule) matchPString(data []byte, offset int64) (bool, int64) {
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
		// Default to 1-byte if not specified
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
		// If it's not a string check (e.g. 'x'), then any valid pstring matches
		return true, dataStart + strLen
	}

	if strings.Contains(string(actualStr), expectedVal) {
		return true, dataStart + strLen
	}

	return false, 0
}

func (r *Rule) matchUTF16(data []byte, offset int64, order binary.ByteOrder) (bool, int64) {
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
		order.PutUint16(pattern[i*2:], u)
	}

	idx := bytes.Index(data[offset:], pattern)
	if idx == -1 {
		return false, 0
	}

	return true, offset + int64(idx) + int64(len(pattern))
}

func (r *Rule) matchSearch(data []byte, offset int64) (bool, int64) {
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
	return true, offset + int64(idx)
}

func (r *Rule) matchNumeric(data []byte, offset int64) (bool, int64) {
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
	if compare(actual, expected, r.Operator) {
		return true, offset
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
