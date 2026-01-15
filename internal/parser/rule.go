package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Rule represents a single line in a magic file
type Rule struct {
	Level    int    // Number of '>' symbols (nesting)
	Offset   int64  // Byte offset to check
	Type     string // e.g., "string", "lelong", "belong", "short"
	Operator string // e.g., "=", "&", ">"
	Value    any    // Can be string, uint32, uint16, uint8
	ValueRaw []byte // The raw bytes of the value
	Message  string // The description (e.g., "PDF document")
	Mime     string // The MIME type (if provided)
	Children []Rule // <--- Add this!
}

func (r Rule) String() string {
	return fmt.Sprintf("L%d @%d Type:%s Value:%v -> %s", r.Level, r.Offset, r.Type, r.Value, r.Message)
}

func (r Rule) RawString() string {
	return fmt.Sprintf("L%d @%d %s=%v -> %s", r.Level, r.Offset, r.Type, r.Value, r.Message)
}

// Match checks if this specific rule matches the provided data.
func (r *Rule) Match(data []byte) bool {
	// 1. Ensure we don't read past the end of the file
	if r.Offset < 0 || r.Offset >= int64(len(data)) {
		return false
	}

	switch r.Type {
	case "string":
		valStr, ok := r.Value.(string)
		if !ok {
			return false
		}

		// Look at the data starting from the offset
		searchArea := data[r.Offset:]
		return bytes.HasPrefix(searchArea, []byte(valStr))

	case "belong": // Big Endian Long (4 bytes)
		if r.Offset+4 > int64(len(data)) {
			return false
		}
		actual := binary.BigEndian.Uint32(data[r.Offset : r.Offset+4])
		expected, ok := r.Value.(uint32)
		if !ok {
			return false
		}
		return actual == expected

	case "lelong": // Little Endian Long (4 bytes)
		if r.Offset+4 > int64(len(data)) {
			return false
		}
		actual := binary.LittleEndian.Uint32(data[r.Offset : r.Offset+4])
		expected, ok := r.Value.(uint32)
		if !ok {
			return false
		}
		return actual == expected

	case "short", "beshort": // Big Endian Short (2 bytes)
		if r.Offset+2 > int64(len(data)) {
			return false
		}
		actual := binary.BigEndian.Uint16(data[r.Offset : r.Offset+2])
		expected, ok := r.Value.(uint16)
		if !ok {
			return false
		}
		return actual == expected

	case "leshort": // Little Endian Short (2 bytes)
		if r.Offset+2 > int64(len(data)) {
			return false
		}
		actual := binary.LittleEndian.Uint16(data[r.Offset : r.Offset+2])
		expected, ok := r.Value.(uint16)
		if !ok {
			return false
		}
		return actual == expected

	case "byte":
		actual := data[r.Offset]
		expected, ok := r.Value.(uint8)
		if !ok {
			return false
		}
		return actual == expected
	default:
		return false
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
