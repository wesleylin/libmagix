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

	offset, isIndirect, ptrOff, ptrType, ptrAdd, err := parseOffset(offsetPart)
	if err != nil {
		return nil, err
	}

	rawType := parts[1]
	rawValue := parts[2]

	// parsing for mask and hashmask
	typeStr, mask, hasMask, err := parseTypeAndMask(rawType)
	if err != nil {
		return nil, err
	}
	op, cleanValueStr := parseOperator(rawValue)

	matchAny := false
	var parsedValue any
	if cleanValueStr == "x" {
		matchAny = true
	} else {
		var err error
		parsedValue, err = parseTypeValue(typeStr, cleanValueStr)
		if err != nil {
			return nil, err
		}
	}

	// Populate ValueRaw for string types (useful for debugging or legacy string matching)
	var valueRaw []byte
	if strVal, ok := parsedValue.(string); ok {
		valueRaw = []byte(strVal)
	}

	return &Rule{
		Level:    level,
		Offset:   offset,
		Type:     typeStr,
		Mask:     mask,
		HasMask:  hasMask,
		Operator: op,
		Value:    parsedValue,
		ValueRaw: valueRaw,
		Message:  parts[3],
		MatchAny: matchAny,

		IsIndirect:    isIndirect,
		PointerOffset: ptrOff,
		PointerType:   ptrType,
		PointerAdd:    ptrAdd,
	}, nil
}

func parseOffset(raw string) (offset int64, isIndirect bool, ptrOff int64, ptrType string, ptrAdd int64, err error) {
	start := strings.Index(raw, "(")
	end := strings.LastIndex(raw, ")")

	if start == -1 || end == -1 || end < start {
		offset, err = strconv.ParseInt(raw, 0, 64)
		if err != nil {
			err = fmt.Errorf("invalid offset: %v", err)
		}
		return
	}

	isIndirect = true
	inner := raw[start+1 : end]
	adjPart := raw[end+1:]

	// 1. Handle inner (offset.type[+adj])
	// Example: 0x3c.l or 0x3c.l+4
	parts := strings.SplitN(inner, ".", 2)
	if len(parts) < 2 {
		err = fmt.Errorf("invalid indirect offset inner part: %s", inner)
		return
	}

	ptrOff, err = strconv.ParseInt(parts[0], 0, 64)
	if err != nil {
		err = fmt.Errorf("invalid pointer offset: %v", err)
		return
	}

	typeAndInnerAdd := parts[1]
	if len(typeAndInnerAdd) == 0 {
		err = fmt.Errorf("missing pointer type in: %s", raw)
		return
	}
	ptrType = string(typeAndInnerAdd[0])

	if len(typeAndInnerAdd) > 1 {
		innerAdj := typeAndInnerAdd[1:]
		ptrAdd, err = strconv.ParseInt(innerAdj, 0, 64)
		if err != nil {
			err = fmt.Errorf("invalid inner pointer adjustment: %v", err)
			return
		}
	}

	// 2. Handle adjustment outside parens (e.g. (0x3c.l)+4)
	if adjPart != "" {
		outerAdj, err2 := strconv.ParseInt(adjPart, 0, 64)
		if err2 != nil {
			err = fmt.Errorf("invalid outer pointer adjustment: %v", err2)
			return
		}
		ptrAdd += outerAdj
	}

	// 3. Handle base offset (if any before parenthesis)
	if start > 0 {
		basePart := raw[:start]
		// In some magic files, it might be ">base(ptr)"
		// but usually 'base' is already stripped by the level handler ('>').
		// If anything is left, we treat it as an addition to the offset.
		baseOff, err3 := strconv.ParseInt(basePart, 0, 64)
		if err3 == nil {
			offset = baseOff
		}
	}

	return
}

func parseTypeValue(typeStr string, valueStr string) (any, error) {
	switch typeStr {
	case "string":
		var processedValue []byte

		// 1. Convert the escaped string into actual bytes
		if strings.Contains(valueStr, `\`) {
			// Wrap in quotes so strconv.Unquote recognizes it as a Go-style string literal
			quoted := `"` + valueStr + `"`
			unquoted, err := strconv.Unquote(quoted)
			if err != nil {
				// Fallback: If unquoting fails, use the raw bytes
				// (This happens if there are invalid escape sequences common in magic files)
				processedValue = []byte(valueStr)
			} else {
				processedValue = []byte(unquoted)
			}
		} else {
			processedValue = []byte(valueStr)
		}

		// Return as string for the 'Value' field
		return string(processedValue), nil

	case "belong", "lelong", "ubelong", "ulelong", "uint32", "long":
		// ParseUint with base 0 automatically handles "0x1234" (Hex), "0123" (Octal), and "123" (Decimal)
		val, err := strconv.ParseUint(valueStr, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid number for %s: %s", typeStr, valueStr)
		}
		return uint32(val), nil

	case "short", "beshort", "leshort", "ubeshort", "uleshort", "uint16":
		val, err := strconv.ParseUint(valueStr, 0, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid number for %s: %s", typeStr, valueStr)
		}
		return uint16(val), nil

	case "byte", "ubyte":
		val, err := strconv.ParseUint(valueStr, 0, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid number for %s: %s", typeStr, valueStr)
		}
		return uint8(val), nil

	default:
		// Unknown types are treated as strings to prevent crashing on future/unknown types
		return valueStr, nil
	}
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

// parseTypeAndMask handles "belong&0xFFFF"
func parseTypeAndMask(raw string) (string, uint64, bool, error) {
	if !strings.Contains(raw, "&") {
		return raw, 0, false, nil
	}

	parts := strings.SplitN(raw, "&", 2)
	typeStr := parts[0]
	maskStr := parts[1]

	// Parse mask (usually hex)
	mask, err := strconv.ParseUint(maskStr, 0, 64)
	if err != nil {
		return "", 0, false, fmt.Errorf("invalid mask: %s", maskStr)
	}

	return typeStr, mask, true, nil
}

// parseOperator handles ">10", "=0x20", "!0"
func parseOperator(raw string) (string, string) {
	// Standard magic operators
	ops := []string{"=", "<", ">", "&", "^", "!"}

	for _, op := range ops {
		if strings.HasPrefix(raw, op) {
			return op, raw[len(op):]
		}
	}

	// Default operator is equality
	return "=", raw
}
