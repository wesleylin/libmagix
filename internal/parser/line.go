package parser

import (
	"fmt"
	"strconv"
	"strings"
	"text/scanner"
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
	var parts []string
	var currentToken strings.Builder
	escaped := false

	// We want 3 specific columns (Offset, Type, Value)
	// and then everything else is the Message (part 4).
	maxParts := 3

	for i, r := range line {
		// If we already have the first 3 parts, the rest of the string is the Message.
		if len(parts) >= maxParts {
			parts = append(parts, strings.TrimSpace(line[i:]))
			return parts
		}

		if escaped {
			currentToken.WriteRune(r)
			escaped = false
			continue
		}

		if r == '\\' {
			escaped = true
			currentToken.WriteRune(r) // Keep the backslash for now so ParseLine can handle it
			continue
		}

		// Split on spaces or tabs
		if r == ' ' || r == '\t' {
			if currentToken.Len() > 0 {
				parts = append(parts, currentToken.String())
				currentToken.Reset()
			}
		} else {
			currentToken.WriteRune(r)
		}
	}

	// Append the last token if we didn't hit the limit (e.g., short lines)
	if currentToken.Len() > 0 {
		parts = append(parts, currentToken.String())
	}

	return parts
}

// splitMagicLine is a helper to handle the specific spacing of magic files
func splitMagicLine2(line string) []string {
	// libmagic uses tabs or multiple spaces as delimiters.
	// A real implementation would need to handle backslash escapes.
	return strings.SplitN(line, "\t", 4)
}

func ParseLine2(line string) (*Rule, error) {
	var s scanner.Scanner
	s.Init(strings.NewReader(line))

	// Configure scanner to handle C-style numbers and strings
	s.Mode = scanner.ScanInts | scanner.ScanFloats | scanner.ScanStrings

	tok := s.Scan()
	if tok == scanner.EOF {
		return nil, nil
	}
	offsetStr := s.TokenText()

	// 2. Parse Type
	tok = s.Scan()
	typeStr := s.TokenText()

	// 3. Parse Test Value
	tok = s.Scan()
	valueStr := s.TokenText()

	// 4. Message rest of line
	restOfLine := line[s.Pos().Offset:]
	message := strings.TrimSpace(restOfLine)

	fmt.Println(offsetStr)

	return &Rule{
		Offset:  0, // Keep as string for now to handle (0x3c) later
		Type:    typeStr,
		Value:   valueStr,
		Message: message,
	}, nil
}
