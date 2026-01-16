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
func (r *Rule) Match(data []byte) bool {
	// 1. Bounds check
	if r.Offset < 0 || r.Offset >= int64(len(data)) {
		return false
	}

	// 2. Handle Strings (Strings don't usually use numeric operators)
	if r.Type == "string" {
		valStr, ok := r.Value.(string)
		if !ok {
			return false
		}
		return bytes.HasPrefix(data[r.Offset:], []byte(valStr))
	}

	// 3. Handle Numeric Types
	// We read the bytes and convert everything to uint64 for easy comparison
	var actual uint64

	switch r.Type {
	case "belong": // Big Endian 4 bytes
		if r.Offset+4 > int64(len(data)) {
			return false
		}
		actual = uint64(binary.BigEndian.Uint32(data[r.Offset : r.Offset+4]))
	case "lelong": // Little Endian 4 bytes
		if r.Offset+4 > int64(len(data)) {
			return false
		}
		actual = uint64(binary.LittleEndian.Uint32(data[r.Offset : r.Offset+4]))
	case "short", "beshort": // Big Endian 2 bytes
		if r.Offset+2 > int64(len(data)) {
			return false
		}
		actual = uint64(binary.BigEndian.Uint16(data[r.Offset : r.Offset+2]))
	case "leshort": // Little Endian 2 bytes
		if r.Offset+2 > int64(len(data)) {
			return false
		}
		actual = uint64(binary.LittleEndian.Uint16(data[r.Offset : r.Offset+2]))
	case "byte": // 1 byte
		actual = uint64(data[r.Offset])
	default:
		// Unknown type
		return false
	}

	// 4. Apply Mask (if exists)
	// Example: >4 byte&0x80
	if r.HasMask {
		actual = actual & r.Mask
	}

	// 5. Compare using the Operator
	// We must cast the expected Value (which is 'any') to uint64 safely
	expected := castToUint64(r.Value)

	return compare(actual, expected, r.Operator)
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
