package parser

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseLine takes a single line from a Magdir file and returns a Rule
func ParseLine(line string) (*Rule, error) {
	if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
		return nil, nil // Skip comments and empty lines
	}

	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil, fmt.Errorf("invalid rule format")
	}

	// 1. Parse Level (count '>')
	level := 0
	offsetStr := fields[0]
	for strings.HasPrefix(offsetStr, ">") {
		level++
		offsetStr = offsetStr[1:]
	}

	// 2. Parse Offset
	offset, _ := strconv.ParseInt(offsetStr, 10, 64)

	// 3. Simple mapping for now
	return &Rule{
		Level:   level,
		Offset:  offset,
		Type:    fields[1],
		Value:   fields[2],
		Message: strings.Join(fields[3:], " "),
	}, nil
}
