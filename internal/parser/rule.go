package parser

import "fmt"

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
	return fmt.Sprintf("L%d @%d %s=%v -> %s", r.Level, r.Offset, r.Type, r.Value, r.Message)
}
