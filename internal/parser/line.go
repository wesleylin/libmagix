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
	parts = joinSpacedOperator(parts)
	if len(parts) < 3 {
		return nil, fmt.Errorf("malformed line (need at least Offset, Type, Value): %s", line)
	}

	// Handle nesting level (count leading '>')
	level := 0
	offsetPart := parts[0]
	for len(offsetPart) > 0 && offsetPart[0] == '>' {
		level++
		offsetPart = offsetPart[1:]
	}

	isRelative := false
	if strings.HasPrefix(offsetPart, "&") {
		isRelative = true
		offsetPart = offsetPart[1:]
	}

	offset, isIndirect, ptrOff, ptrType, ptrOp, ptrArg, outerAdd, ptrRelative, err := parseOffset(offsetPart)
	if err != nil {
		return nil, err
	}
	if ptrRelative {
		isRelative = true
	}

	rawType := parts[1]
	rawValue := parts[2]

	var searchRange int64
	var pstringLenType string
	if strings.HasPrefix(rawType, "search") && strings.Contains(rawType, "/") {
		tParts := strings.SplitN(rawType, "/", 2)
		rawType = tParts[0]
		searchRange, _ = strconv.ParseInt(tParts[1], 0, 64)
	} else if strings.HasPrefix(rawType, "pstring") && strings.Contains(rawType, "/") {
		tParts := strings.SplitN(rawType, "/", 2)
		rawType = tParts[0]
		pstringLenType = tParts[1]
	}

	// parsing for mask and hashmask
	typeStr, mask, hasMask, err := parseTypeAndMask(rawType)
	if err != nil {
		return nil, err
	}
	typeStr, typeOp, typeOpArg := splitNumericOp(typeStr)
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

	message := ""
	if len(parts) >= 4 {
		message = parts[3]
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
		Message:  message,
		MatchAny: matchAny,

		IsIndirect:        isIndirect,
		PointerOffset:     ptrOff,
		PointerType:       ptrType,
		PointerOp:         ptrOp,
		PointerAdd:        outerAdd,
		PointerAdjustment: ptrArg,

		SearchRange:       searchRange,
		PStringLengthType: pstringLenType,
		IsRelative:        isRelative,
		TypeOp:            typeOp,
		TypeOpArg:         typeOpArg,
	}, nil
}

// splitNumericOp parses "uleshort/256" and "uleshort%256".
// String flags such as "string/c" are left unchanged.
func splitNumericOp(typeStr string) (string, string, uint64) {
	for _, op := range []string{"/", "%"} {
		idx := strings.Index(typeStr, op)
		if idx <= 0 {
			continue
		}
		base := typeStr[:idx]
		if !isNumericType(base) {
			continue
		}
		arg, err := strconv.ParseUint(typeStr[idx+1:], 0, 64)
		if err != nil || arg == 0 {
			continue
		}
		return base, op, arg
	}
	return typeStr, "", 0
}

func isNumericType(typeStr string) bool {
	switch typeStr {
	case "byte", "ubyte",
		"short", "beshort", "leshort", "ubeshort", "uleshort", "uint16",
		"long", "belong", "lelong", "ubelong", "ulelong", "uint32",
		"quad", "bequad", "lequad", "ubequad", "ulequad":
		return true
	default:
		return false
	}
}

func parseOffset(raw string) (offset int64, isIndirect bool, ptrOff int64, ptrType string, ptrOp string, ptrArg int64, outerAdd int64, ptrRelative bool, err error) {
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

	ptrRaw := parts[0]
	if strings.HasPrefix(ptrRaw, "&") {
		ptrRelative = true
		ptrRaw = ptrRaw[1:]
	}
	ptrOff, err = strconv.ParseInt(ptrRaw, 0, 64)
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
		if innerAdj != "" && strings.ContainsRune("+-*/%&|^", rune(innerAdj[0])) {
			ptrOp = innerAdj[:1]
			innerAdj = innerAdj[1:]
		} else {
			ptrOp = "+"
		}
		ptrArg, err = strconv.ParseInt(innerAdj, 0, 64)
		if err != nil {
			err = fmt.Errorf("invalid inner pointer adjustment: %v", err)
			return
		}
	}

	// 2. Handle adjustment outside parens (e.g. (0x3c.l)+4)
	if adjPart != "" {
		outerAdd, err = strconv.ParseInt(adjPart, 0, 64)
		if err != nil {
			err = fmt.Errorf("invalid outer pointer adjustment: %v", err)
			return
		}
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
	case "string", "pstring", "bestring16", "lestring16", "regex", "search":
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
		val, err := parseMagicUint(valueStr, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid number for %s: %s", typeStr, valueStr)
		}
		return uint32(val), nil

	case "short", "beshort", "leshort", "ubeshort", "uleshort", "uint16":
		val, err := parseMagicUint(valueStr, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid number for %s: %s", typeStr, valueStr)
		}
		return uint16(val), nil

	case "byte", "ubyte":
		val, err := parseMagicUint(valueStr, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid number for %s: %s", typeStr, valueStr)
		}
		return uint8(val), nil

	case "quad", "bequad", "lequad", "ubequad", "ulequad":
		val, err := parseMagicUint(valueStr, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid number for %s: %s", typeStr, valueStr)
		}
		return val, nil

	case "name", "use":
		return valueStr, nil

	default:
		// Unknown types are treated as strings to prevent crashing on future/unknown types
		return valueStr, nil
	}
}

// parseMagicUint parses an unsigned magic value. A negative literal such as
// -1 is kept as the two's-complement bit pattern of the given width.
func parseMagicUint(valueStr string, bitSize int) (uint64, error) {
	val, err := strconv.ParseUint(valueStr, 0, bitSize)
	if err == nil {
		return val, nil
	}
	signed, serr := strconv.ParseInt(valueStr, 0, bitSize)
	if serr != nil {
		return 0, err
	}
	return uint64(signed), nil
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
				if len(parts) == 3 && isLoneOperator(parts[2]) {
					maxParts = 4
				}
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

// joinSpacedOperator turns "beshort > 1" into value ">1".
// Magic files sometimes put a space between the operator and the number.
func joinSpacedOperator(parts []string) []string {
	if len(parts) < 4 || !isLoneOperator(parts[2]) {
		return parts
	}
	parts[2] = parts[2] + parts[3]
	return append(parts[:3], parts[4:]...)
}

func isLoneOperator(s string) bool {
	switch s {
	case "=", "<", ">", "&", "^", "!":
		return true
	default:
		return false
	}
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
