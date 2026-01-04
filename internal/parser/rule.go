package parser

import (
	"bytes"
	"fmt"
)

// Rule represents a single line in a magic file
type Rule struct {
	Level    int    // Number of '>' symbols (nesting)
	Offset   int64  // Byte offset to check
	Type     string // e.g., "string", "lelong", "belong", "short"
	Operator string // e.g., "=", "&", ">"
	Value    any    // The parsed value to compare against
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

	// We will add "belong", "lelong", etc. next!
	default:
		return false
	}
}
