package parser

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ParseLine processes a single raw line from a magic file.
func ParseLine(line string) (*Rule, error) {
	line = trimMagicLine(line)
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

	rawType, searchRange, pstringLenType, offsetAtStart, stringFlags := parseStringModifiers(rawType)

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
		OffsetAtStart:     offsetAtStart,
		PStringLengthType: pstringLenType,
		StringFlags:       stringFlags,
		IsRelative:        isRelative,
		PointerRelative:   ptrRelative,
		TypeOp:            typeOp,
		TypeOpArg:         typeOpArg,
	}, nil
}

// parseStringModifiers splits "search/1", "regex/4s", "string/wt", and "pstring/H".
// A leading number is the search window. 's' makes continuations relative to
// the start of the match. Pascal-string length letters select the length field.
// 't' and 'b' choose the text and binary passes. 'w' makes a pattern space
// optional whitespace, 'W' makes it required whitespace, and 'T' trims the
// bytes printed by %s.
func parseStringModifiers(raw string) (typeStr string, searchRange int64, pstringLen string, offsetAtStart bool, flags uint32) {
	typeStr = raw
	slash := strings.IndexByte(raw, '/')
	if slash <= 0 {
		return
	}
	switch raw[:slash] {
	case "string", "search", "regex", "pstring":
	default:
		return
	}
	typeStr = raw[:slash]
	rest := raw[slash+1:]
	for i := 0; i < len(rest); {
		if rest[i] == '/' {
			i++
			continue
		}
		if rest[i] >= '0' && rest[i] <= '9' {
			j := i + 1
			for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
				j++
			}
			if rest[i] == '0' && i+1 < len(rest) && (rest[i+1] == 'x' || rest[i+1] == 'X') {
				j = i + 2
				for j < len(rest) && isHex(rest[j]) {
					j++
				}
			}
			if n, err := strconv.ParseInt(rest[i:j], 0, 64); err == nil {
				searchRange = n
			}
			i = j
			continue
		}
		switch rest[i] {
		case 's':
			offsetAtStart = true
		case 'B', 'H', 'h', 'L':
			pstringLen = string(rest[i])
		case 'l':
			// On a regex, /l is the line-count flag. On a pstring it is the length field.
			if typeStr == "regex" {
				flags |= StringRegexLineCount
			} else {
				pstringLen = "l"
			}
		case 't':
			flags |= StringText
		case 'b':
			flags |= StringBinary
		case 'w':
			flags |= StringOptionalWhitespace
		case 'W':
			flags |= StringCompactWhitespace
		case 'T':
			flags |= StringTrim
		case 'c':
			flags |= StringIgnoreLower
		case 'C':
			flags |= StringIgnoreUpper
		}
		i++
	}
	return
}

// splitNumericOp parses "uleshort/256", "uleshort%256", and "leldate+631065600".
// String flags such as "string/c" are left unchanged.
func splitNumericOp(typeStr string) (string, string, uint64) {
	for _, op := range []string{"+", "-", "/", "%"} {
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
		"short", "beshort", "leshort", "ubeshort", "uleshort", "ushort", "uint16",
		"long", "belong", "lelong", "ubelong", "ulelong", "uint32",
		"quad", "bequad", "lequad", "ubequad", "ulequad",
		"date", "ldate", "bedate", "beldate", "ledate", "leldate", "medate", "meldate",
		"qdate", "lqdate", "beqdate", "beqldate", "leqdate", "leqldate",
		"msdosdate", "lemsdosdate", "bemsdosdate",
		"msdostime", "lemsdostime", "bemsdostime":
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

// trimMagicLine drops unescaped leading and trailing space and tabs.
// A trailing "\ " is part of the value, as in the Python "def\ " test.
func trimMagicLine(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') {
		i++
	}
	s = s[i:]
	end := len(s)
	for end > 0 {
		c := s[end-1]
		if c != ' ' && c != '\t' && c != '\r' {
			break
		}
		n := 0
		for j := end - 2; j >= 0 && s[j] == '\\'; j-- {
			n++
		}
		if n%2 == 1 {
			break
		}
		end--
	}
	return s[:end]
}

// unescapeMagic decodes magic string escapes. Octal runs are one to three
// digits, so "\0" is a NUL. Go's strconv.Unquote rejects that form.
func unescapeMagic(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte('\v')
		case '\\':
			b.WriteByte('\\')
		case ' ':
			b.WriteByte(' ')
		case 'x':
			if i+1 >= len(s) || !isHex(s[i+1]) {
				b.WriteByte('x')
				break
			}
			i++
			v := hexVal(s[i])
			if i+1 < len(s) && isHex(s[i+1]) {
				i++
				v = v<<4 | hexVal(s[i])
			}
			b.WriteByte(v)
		default:
			if s[i] < '0' || s[i] > '7' {
				b.WriteByte(s[i])
				break
			}
			v := s[i] - '0'
			for n := 0; n < 2 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '7'; n++ {
				i++
				v = v*8 + (s[i] - '0')
			}
			b.WriteByte(v)
		}
	}
	return b.String()
}

// stripCSize removes a C integer suffix such as the L in 0x1b031336L.
func stripCSize(s string) string {
	if s == "" {
		return s
	}
	i := len(s) - 1
	switch s[i] {
	case 'l', 'L', 's', 'S', 'h', 'H', 'b', 'B', 'c', 'C':
		i--
	default:
		return s
	}
	if i >= 0 && (s[i] == 'u' || s[i] == 'U') {
		i--
	}
	return s[:i+1]
}

// encodeGUID stores a magic GUID the way file compares it: the first three
// fields are little-endian and the last two are left as written.
func encodeGUID(s string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(raw) != 16 {
		return nil, fmt.Errorf("invalid guid: %s", s)
	}
	out := []byte{
		raw[3], raw[2], raw[1], raw[0],
		raw[5], raw[4],
		raw[7], raw[6],
	}
	out = append(out, raw[8:]...)
	return out, nil
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func parseTypeValue(typeStr string, valueStr string) (any, error) {
	switch typeStr {
	case "string", "pstring", "bestring16", "lestring16", "regex", "search", "guid":
		var processedValue []byte

		processedValue = []byte(unescapeMagic(valueStr))
		if typeStr == "guid" {
			b, err := encodeGUID(string(processedValue))
			if err != nil {
				return nil, err
			}
			return string(b), nil
		}

		// Return as string for the 'Value' field
		return string(processedValue), nil

	case "belong", "lelong", "ubelong", "ulelong", "uint32", "long":
		val, err := parseMagicUint(valueStr, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid number for %s: %s", typeStr, valueStr)
		}
		return uint32(val), nil

	case "short", "beshort", "leshort", "ubeshort", "uleshort", "ushort", "uint16":
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

	case "quad", "bequad", "lequad", "ubequad", "ulequad",
		"qdate", "lqdate", "beqdate", "beqldate", "leqdate", "leqldate":
		val, err := parseMagicUint(valueStr, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid number for %s: %s", typeStr, valueStr)
		}
		return val, nil

	case "date", "ldate", "bedate", "beldate", "ledate", "leldate", "medate", "meldate":
		val, err := parseMagicUint(valueStr, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid number for %s: %s", typeStr, valueStr)
		}
		return uint32(val), nil

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
	if val, err := parseMagicUintRaw(valueStr, bitSize); err == nil {
		return val, nil
	}
	// 0x1b031336L is a C integer. The suffix is only eaten when it is not
	// part of the number, so a hex digit such as the c in 0xc stays.
	trimmed := stripCSize(valueStr)
	if trimmed != valueStr {
		if val, err := parseMagicUintRaw(trimmed, bitSize); err == nil {
			return val, nil
		}
	}
	return 0, fmt.Errorf("invalid number %s", valueStr)
}

func parseMagicUintRaw(valueStr string, bitSize int) (uint64, error) {
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
