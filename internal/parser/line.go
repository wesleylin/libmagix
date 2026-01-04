package parser

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseLine processes a single raw line from a magic file.
func ParseLine(line string) (*Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}

	// We use a custom splitter or regex because 'strings.Fields'
	// fails on escaped spaces (e.g., 'string  \ name\ with\ space')
	parts := splitMagicLine(line)
	if len(parts) < 4 {
		return nil, fmt.Errorf("malformed line: %s", line)
	}

	// Handle nesting level (count leading '>')
	level := 0
	offsetPart := parts[0]
	for len(offsetPart) > 0 && offsetPart[0] == '>' {
		level++
		offsetPart = offsetPart[1:]
	}

	offset, err := strconv.ParseInt(offsetPart, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid offset: %v", err)
	}

	rawValue := parts[2]
	var processedValue []byte

	// 2. Convert the escaped string into actual bytes
	if strings.Contains(rawValue, `\`) {
		// Wrap in quotes so strconv.Unquote recognizes it as a Go-style string literal
		quoted := `"` + rawValue + `"`
		unquoted, err := strconv.Unquote(quoted)
		if err != nil {
			// Fallback: If unquoting fails, use the raw bytes
			// (This happens if there are invalid escape sequences)
			processedValue = []byte(rawValue)
		} else {
			processedValue = []byte(unquoted)
		}
	} else {
		processedValue = []byte(rawValue)
	}

	return &Rule{
		Level:    level,
		Offset:   offset,
		Type:     parts[1],
		Value:    parts[2],
		ValueRaw: processedValue,
		Message:  parts[3],
	}, nil
}

// splitMagicLine is a helper to handle the specific spacing of magic files
func splitMagicLine(line string) []string {
	// libmagic uses tabs or multiple spaces as delimiters.
	// A real implementation would need to handle backslash escapes.
	return strings.SplitN(line, "\t", 4)
}
