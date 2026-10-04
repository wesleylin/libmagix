package parser

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strings"
)

// Handler is a function type for matching rules against data
type Handler func(data []byte, r *Rule, offset int64) (bool, int64)

// matchString matches string rules against data
func matchString(data []byte, r *Rule, offset int64) (bool, int64) {
	valStr, ok := r.Value.(string)
	if !ok {
		return false, 0
	}
	if offset < 0 || offset >= int64(len(data)) {
		return false, 0
	}
	// Empty string matches at the current offset (must be within bounds)
	if valStr == "" && (r.Operator == "" || r.Operator == "=") {
		return true, offset
	}
	pattern := []byte(valStr)
	if r.StringFlags&(StringOptionalWhitespace|StringCompactWhitespace|StringIgnoreLower|StringIgnoreUpper) != 0 &&
		(r.Operator == "" || r.Operator == "=") {
		if matchSpaced(data[offset:], pattern, r.StringFlags) {
			return true, offset + int64(len(pattern))
		}
		return false, 0
	}
	switch r.Operator {
	case ">", "<":
		end := offset + int64(len(pattern))
		if end > int64(len(data)) {
			return false, 0
		}
		cmp := bytes.Compare(data[offset:end], pattern)
		if r.Operator == ">" && cmp > 0 || r.Operator == "<" && cmp < 0 {
			return true, end
		}
		return false, 0
	case "!":
		if bytes.HasPrefix(data[offset:], pattern) {
			return false, 0
		}
		return true, offset
	default:
		if bytes.HasPrefix(data[offset:], pattern) {
			return true, offset + int64(len(pattern))
		}
		return false, 0
	}
}

// matchSpaced compares a pattern whose spaces are whitespace classes.
// A pattern space with /w matches zero or more file whitespace bytes.
// A pattern space with /W matches one or more. The reported match end
// stays at offset+len(pattern), which is what continuations such as
// ">&-1" are measured from.
func matchSpaced(file, pat []byte, flags uint32) bool {
	i, j := 0, 0
	for j < len(pat) {
		if flags&StringCompactWhitespace != 0 && isMagicSpace(pat[j]) {
			j++
			if i >= len(file) || !isMagicSpace(file[i]) {
				return false
			}
			i++
			if j >= len(pat) || !isMagicSpace(pat[j]) {
				for i < len(file) && isMagicSpace(file[i]) {
					i++
				}
			}
			continue
		}
		if flags&StringOptionalWhitespace != 0 && isMagicSpace(pat[j]) {
			j++
			for i < len(file) && isMagicSpace(file[i]) {
				i++
			}
			continue
		}
		if i >= len(file) {
			return false
		}
		fb, pb := file[i], pat[j]
		if flags&StringIgnoreLower != 0 && pb >= 'a' && pb <= 'z' && fb >= 'A' && fb <= 'Z' {
			fb += 'a' - 'A'
		}
		if flags&StringIgnoreUpper != 0 && pb >= 'A' && pb <= 'Z' && fb >= 'a' && fb <= 'z' {
			fb -= 'a' - 'A'
		}
		if fb != pb {
			return false
		}
		i++
		j++
	}
	return true
}

func isMagicSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

// matchPString matches Pascal string rules against data
func matchPString(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 || offset >= int64(len(data)) {
		return false, 0
	}

	var strLen int
	var headerLen int64

	switch r.PStringLengthType {
	case "B": // 1-byte length
		strLen = int(data[offset])
		headerLen = 1
	case "h": // 2-byte little-endian: low byte first, then high byte
		if offset+2 > int64(len(data)) {
			return false, 0
		}
		// First byte is low-order, second byte is high-order
		strLen = int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		headerLen = 2
	case "H": // 2-byte big-endian: high byte first, then low byte
		if offset+2 > int64(len(data)) {
			return false, 0
		}
		strLen = int(binary.BigEndian.Uint16(data[offset : offset+2]))
		headerLen = 2
	case "l": // 4-byte little-endian
		if offset+4 > int64(len(data)) {
			return false, 0
		}
		// bytes[0] is LSB, bytes[3] is MSB
		strLen = int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		headerLen = 4
	case "L": // 4-byte big-endian
		if offset+4 > int64(len(data)) {
			return false, 0
		}
		strLen = int(binary.BigEndian.Uint32(data[offset : offset+4]))
		headerLen = 4
	default:
		// Default to 1-byte length
		strLen = int(data[offset])
		headerLen = 1
	}

	dataStart := offset + int64(headerLen)
	if dataStart > int64(len(data)) {
		return false, 0
	}

	maxRead := len(data) - int(dataStart)
	if strLen > maxRead {
		strLen = maxRead
	}

	actualStr := data[dataStart : dataStart+int64(strLen)]
	expectedVal, ok := r.Value.(string)
	if !ok || r.MatchAny || expectedVal == "" {
		// 'x' leaves the offset on the first NUL or newline, where file's
		// strlen stops, so a following "&1" sees the next field key.
		n := bytes.IndexAny(actualStr, "\x00\r\n")
		if n < 0 {
			n = len(actualStr)
		}
		return true, dataStart + int64(n)
	}

	if strings.Contains(string(actualStr), expectedVal) {
		return true, dataStart + int64(strLen)
	}

	return false, 0
}

// matchUTF16LE matches UTF-16 little-endian string rules against data
func matchUTF16LE(data []byte, r *Rule, offset int64) (bool, int64) {
	expectedVal, ok := r.Value.(string)
	if !ok {
		return false, 0
	}

	if offset < 0 || offset+2 > int64(len(data)) {
		return false, 0
	}

	// Empty pattern matches at the offset after minimum UTF-16 header (2 bytes)
	if expectedVal == "" {
		return true, offset + 2
	}

	patternLen := len(expectedVal) * 2
	if int64(patternLen)+offset > int64(len(data)) {
		return false, 0
	}

	utf16Buf := make([]uint16, patternLen/2)
	for i := 0; i < len(expectedVal); i++ {
		utf16Buf[i] = uint16(rune(expectedVal[i]))
	}

	pattern := make([]byte, patternLen)
	for i := 0; i < len(utf16Buf); i++ {
		binary.LittleEndian.PutUint16(pattern[i*2:], utf16Buf[i])
	}

	if !bytes.Equal(data[offset:offset+int64(patternLen)], pattern) {
		return false, 0
	}
	return true, offset + int64(patternLen)
}

// matchUTF16BE matches UTF-16 big-endian string rules against data
func matchUTF16BE(data []byte, r *Rule, offset int64) (bool, int64) {
	expectedVal, ok := r.Value.(string)
	if !ok {
		return false, 0
	}

	if offset < 0 || offset+2 > int64(len(data)) {
		return false, 0
	}

	utf16Buf := make([]uint16, len(expectedVal))
	for i, runeVal := range expectedVal {
		utf16Buf[i] = uint16(runeVal)
	}

	pattern := make([]byte, len(utf16Buf)*2)
	for i, u := range utf16Buf {
		binary.BigEndian.PutUint16(pattern[i*2:], u)
	}

	if int64(len(pattern))+offset > int64(len(data)) || !bytes.Equal(data[offset:offset+int64(len(pattern))], pattern) {
		return false, 0
	}
	return true, offset + int64(len(pattern))
}

// matchSearch matches search rules against data within a range.
// Important: If it finds a match at byte 500 relative to offset, it returns true, 500.
func matchSearch(data []byte, r *Rule, offset int64) (bool, int64) {
	valStr, ok := r.Value.(string)
	if !ok {
		return false, 0
	}
	if offset < 0 || offset > int64(len(data)) {
		return false, 0
	}

	pattern := []byte(valStr)
	maxSearchEnd := int64(len(data))

	// The range counts starting positions. The pattern may extend past it,
	// which is why search/1 can match a string longer than one byte.
	if r.SearchRange > 0 {
		end := offset + r.SearchRange + int64(len(pattern)) - 1
		if end < maxSearchEnd {
			maxSearchEnd = end
		}
	}

	if offset > maxSearchEnd {
		return false, 0
	}

	idx := bytes.Index(data[offset:maxSearchEnd], pattern)
	found := idx != -1 && (r.SearchRange <= 0 || int64(idx) < r.SearchRange)
	// "!" succeeds when the pattern is absent. Continuations stay at the
	// start offset, since nothing was consumed.
	if r.Operator == "!" {
		if found {
			return false, 0
		}
		return true, offset
	}
	if !found {
		return false, 0
	}
	// Continuations are relative to the end of the match unless /s is set.
	if r.OffsetAtStart {
		return true, offset + int64(idx)
	}
	return true, offset + int64(idx) + int64(len(pattern))
}

// matchRegex matches an extended regular expression within a bounded window.
func matchRegex(data []byte, r *Rule, offset int64) (bool, int64) {
	_, start, end, ok := findRegex(data, r, offset)
	if !ok {
		return false, 0
	}
	if r.OffsetAtStart {
		return true, start
	}
	return true, end
}

// matchByte matches byte rules against data
func matchByte(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 || offset >= int64(len(data)) {
		return false, 0
	}
	actual := uint64(data[offset])
	expected := castToUint64(r.Value)
	if r.HasMask {
		actual &= r.Mask
		expected &= r.Mask
	}
	actual = applyTypeOp(actual, r)

	matched := compare(actual, expected, r.Operator)
	if !matched {
		return false, offset
	}
	return true, offset + 1
}

// matchShortLE matches little-endian short (2 bytes) rules against data
func matchShortLE(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 || offset+2 > int64(len(data)) {
		return false, 0
	}
	actual := uint64(binary.LittleEndian.Uint16(data[offset : offset+2]))
	expected := castToUint64(r.Value)

	if r.HasMask {
		actual &= r.Mask
		expected &= r.Mask
	}
	actual = applyTypeOp(actual, r)

	matched := compare(actual, expected, r.Operator)
	if !matched {
		return false, offset
	}
	return true, offset + 2
}

// matchShortBE matches big-endian short (2 bytes) rules against data
func matchShortBE(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 {
		return false, 0
	}
	if offset+2 > int64(len(data)) {
		return false, 0
	}
	actual := uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
	expected := castToUint64(r.Value)

	if r.HasMask {
		// Apply mask to both actual and expected for consistent comparison
		actual = actual & r.Mask
		expected = expected & r.Mask
	}
	actual = applyTypeOp(actual, r)

	matched := compare(actual, expected, r.Operator)
	if !matched {
		return false, offset
	}
	return true, offset + 2
}

// matchLongLE matches little-endian long (4 bytes) rules against data
func matchLongLE(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 {
		return false, 0
	}
	if offset+4 > int64(len(data)) {
		return false, 0
	}
	actual := uint64(binary.LittleEndian.Uint32(data[offset : offset+4]))
	expected := castToUint64(r.Value)

	if r.HasMask {
		actual &= r.Mask
		expected &= r.Mask
	}
	actual = applyTypeOp(actual, r)

	matched := compare(actual, expected, r.Operator)
	if !matched {
		return false, offset
	}
	return true, offset + 4
}

// matchLongBE matches big-endian long (4 bytes) rules against data
func matchLongBE(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 {
		return false, 0
	}
	if offset+4 > int64(len(data)) {
		return false, 0
	}
	actual := uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
	expected := castToUint64(r.Value)

	if r.HasMask {
		actual &= r.Mask
		expected &= r.Mask
	}
	actual = applyTypeOp(actual, r)

	matched := compare(actual, expected, r.Operator)
	if !matched {
		return false, offset
	}
	return true, offset + 4
}

// matchNumericHandler is a fallback handler for unknown types that defaults to numeric matching
func matchNumericHandler(data []byte, r *Rule, offset int64) (bool, int64) {
	if offset < 0 || offset >= int64(len(data)) {
		return false, 0
	}

	var actual uint64
	var stride int64
	switch r.Type {
	case "belong", "ubelong", "uint32", "long": // Big Endian 4 bytes
		if offset+4 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
		stride = 4
	case "lelong", "ulelong", "ledate", "leldate":
		if offset+4 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.LittleEndian.Uint32(data[offset : offset+4]))
		stride = 4
	case "bedate", "beldate":
		if offset+4 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
		stride = 4
	case "medate", "meldate":
		if offset+4 > int64(len(data)) {
			return false, 0
		}
		actual = readMiddleEndian(data[offset : offset+4])
		stride = 4
	case "date", "ldate":
		if offset+4 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.NativeEndian.Uint32(data[offset : offset+4]))
		stride = 4
	case "leqdate", "leqldate":
		if offset+8 > int64(len(data)) {
			return false, 0
		}
		actual = binary.LittleEndian.Uint64(data[offset : offset+8])
		stride = 8
	case "beqdate", "beqldate":
		if offset+8 > int64(len(data)) {
			return false, 0
		}
		actual = binary.BigEndian.Uint64(data[offset : offset+8])
		stride = 8
	case "qdate", "lqdate":
		if offset+8 > int64(len(data)) {
			return false, 0
		}
		actual = binary.NativeEndian.Uint64(data[offset : offset+8])
		stride = 8
	case "short", "beshort", "ubeshort": // Big Endian 2 bytes
		if offset+2 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
		stride = 2
	case "ushort": // native-endian unsigned short
		if offset+2 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.NativeEndian.Uint16(data[offset : offset+2]))
		stride = 2
	case "leshort", "uleshort", "uint16": // Little Endian 2 bytes
		if offset+2 > int64(len(data)) {
			return false, 0
		}
		actual = uint64(binary.LittleEndian.Uint16(data[offset : offset+2]))
		stride = 2
	case "byte", "ubyte": // 1 byte
		actual = uint64(data[offset])
		stride = 1
	default:
		return false, 0
	}

	if r.HasMask {
		actual = actual & r.Mask
	}
	actual = applyTypeOp(actual, r)

	expected := castToUint64(r.Value)

	matched := compare(actual, expected, r.Operator)
	if !matched {
		return false, offset
	}
	return true, offset + stride
}

// regexEnd is the exclusive end of the window a regex may search.
// regex/Nl treats the range as a line count and stops after that many
// lines, looking at most 80 bytes per line. A plain range is a byte count.
// Zero means the rest of the buffer, capped at 8192 bytes.
func regexEnd(data []byte, offset int64, r *Rule) int64 {
	nbytes := int64(len(data))
	if offset < 0 || offset > nbytes {
		return offset
	}
	var lineCount, byteCount int64
	if r.StringFlags&StringRegexLineCount != 0 {
		lineCount = r.SearchRange
		byteCount = lineCount * 80
	} else {
		byteCount = r.SearchRange
	}
	if byteCount == 0 || byteCount > nbytes-offset {
		byteCount = nbytes - offset
	}
	if byteCount > 8192 {
		byteCount = 8192
	}
	end := offset + byteCount
	if lineCount == 0 {
		return end
	}
	last := end
	b := offset
	lines := lineCount
	for lines > 0 && b < end {
		nl := bytes.IndexByte(data[b:end], '\n')
		cr := bytes.IndexByte(data[b:end], '\r')
		switch {
		case nl >= 0:
			b += int64(nl)
		case cr >= 0:
			b += int64(cr)
		default:
			return end
		}
		if b < end-1 && data[b] == '\r' && data[b+1] == '\n' {
			b++
		}
		if b < end-1 && data[b] == '\n' {
			b++
		}
		last = b
		lines--
		b++
	}
	if lines > 0 {
		return end
	}
	return last
}

// excludeNewline makes [^...] stop at a newline, matching REG_NEWLINE.
func excludeNewline(pat string) string {
	var b strings.Builder
	for i := 0; i < len(pat); {
		if pat[i] == '\\' && i+1 < len(pat) {
			b.WriteByte(pat[i])
			b.WriteByte(pat[i+1])
			i += 2
			continue
		}
		if pat[i] == '[' && i+1 < len(pat) && pat[i+1] == '^' {
			b.WriteString("[^")
			i += 2
			start := i
			if i < len(pat) && pat[i] == ']' {
				i++
			}
			hasNL := false
			for i < len(pat) && pat[i] != ']' {
				if pat[i] == '\\' && i+1 < len(pat) {
					if pat[i+1] == 'n' {
						hasNL = true
					}
					i += 2
					continue
				}
				if pat[i] == '\n' {
					hasNL = true
				}
				i++
			}
			if !hasNL {
				b.WriteString(`\n`)
			}
			b.WriteString(pat[start:i])
			if i < len(pat) && pat[i] == ']' {
				b.WriteByte(']')
				i++
			}
			continue
		}
		b.WriteByte(pat[i])
		i++
	}
	return b.String()
}

func findRegex(data []byte, r *Rule, offset int64) (string, int64, int64, bool) {
	pat, ok := r.Value.(string)
	if !ok || offset < 0 || offset > int64(len(data)) {
		return "", 0, 0, false
	}
	end := regexEnd(data, offset, r)
	// file hands the window to regexec. A C string ends at the first NUL,
	// and the last byte of the window is overwritten with NUL so it is not
	// part of the match. Bytes after that NUL, such as a ".png" later in a
	// zip, are invisible.
	if end > offset {
		if nul := bytes.IndexByte(data[offset:end], 0); nul >= 0 {
			end = offset + int64(nul)
		} else {
			end--
		}
	}
	// file compiles with REG_NEWLINE: ^ and $ match at line edges, and a
	// negated class does not consume a newline.
	pat = "(?m)" + excludeNewline(pat)
	re, err := regexp.Compile(pat)
	if err != nil {
		return "", 0, 0, false
	}
	loc := re.FindIndex(data[offset:end])
	if loc == nil {
		return "", 0, 0, false
	}
	start := offset + int64(loc[0])
	matchEnd := offset + int64(loc[1])
	return string(data[start:matchEnd]), start, matchEnd, true
}

func matchGUID(data []byte, r *Rule, offset int64) (bool, int64) {
	expected, ok := r.Value.(string)
	if !ok || offset < 0 || offset+16 > int64(len(data)) {
		return false, 0
	}
	if string(data[offset:offset+16]) != expected {
		return false, offset
	}
	return true, offset + 16
}

func matchQuadLE(data []byte, r *Rule, offset int64) (bool, int64) {
	return matchQuad(data, r, offset, binary.LittleEndian)
}

func matchQuadBE(data []byte, r *Rule, offset int64) (bool, int64) {
	return matchQuad(data, r, offset, binary.BigEndian)
}

func matchQuad(data []byte, r *Rule, offset int64, order binary.ByteOrder) (bool, int64) {
	if offset < 0 || offset+8 > int64(len(data)) {
		return false, 0
	}
	actual := order.Uint64(data[offset : offset+8])
	expected := castToUint64(r.Value)
	if r.HasMask {
		actual &= r.Mask
		expected &= r.Mask
	}
	actual = applyTypeOp(actual, r)
	if !compare(actual, expected, r.Operator) {
		return false, offset
	}
	return true, offset + 8
}

// readMiddleEndian decodes a PDP-11 long: the two little-endian halves are swapped.
func readMiddleEndian(b []byte) uint64 {
	le := binary.LittleEndian.Uint32(b)
	return uint64((le&0xffff)<<16 | (le >> 16))
}

// applyTypeOp divides or reduces the file value (uleshort/256, ulelong%256).
func applyTypeOp(actual uint64, r *Rule) uint64 {
	if r.TypeOpArg == 0 {
		return actual
	}
	switch r.TypeOp {
	case "/":
		return actual / r.TypeOpArg
	case "%":
		return actual % r.TypeOpArg
	case "+":
		return actual + r.TypeOpArg
	case "-":
		if actual < r.TypeOpArg {
			return 0
		}
		return actual - r.TypeOpArg
	default:
		return actual
	}
}

// extractedNumber reads a numeric field and applies the mask and type operator.
func extractedNumber(data []byte, r *Rule, offset int64) (uint64, bool) {
	if offset < 0 {
		return 0, false
	}
	var actual uint64
	switch r.Type {
	case "byte", "ubyte":
		if offset >= int64(len(data)) {
			return 0, false
		}
		actual = uint64(data[offset])
	case "ushort":
		if offset+2 > int64(len(data)) {
			return 0, false
		}
		actual = uint64(binary.NativeEndian.Uint16(data[offset : offset+2]))
	case "leshort", "uleshort", "uint16", "lemsdosdate", "lemsdostime":
		if offset+2 > int64(len(data)) {
			return 0, false
		}
		actual = uint64(binary.LittleEndian.Uint16(data[offset : offset+2]))
	case "short", "beshort", "ubeshort", "msdosdate", "msdostime", "bemsdosdate", "bemsdostime":
		if offset+2 > int64(len(data)) {
			return 0, false
		}
		actual = uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
	case "lelong", "ulelong", "uint32", "ledate", "leldate":
		if offset+4 > int64(len(data)) {
			return 0, false
		}
		actual = uint64(binary.LittleEndian.Uint32(data[offset : offset+4]))
	case "bedate", "beldate":
		if offset+4 > int64(len(data)) {
			return 0, false
		}
		actual = uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
	case "medate", "meldate":
		if offset+4 > int64(len(data)) {
			return 0, false
		}
		actual = readMiddleEndian(data[offset : offset+4])
	case "date", "ldate":
		if offset+4 > int64(len(data)) {
			return 0, false
		}
		actual = uint64(binary.NativeEndian.Uint32(data[offset : offset+4]))
	case "leqdate", "leqldate":
		if offset+8 > int64(len(data)) {
			return 0, false
		}
		actual = binary.LittleEndian.Uint64(data[offset : offset+8])
	case "beqdate", "beqldate":
		if offset+8 > int64(len(data)) {
			return 0, false
		}
		actual = binary.BigEndian.Uint64(data[offset : offset+8])
	case "qdate", "lqdate":
		if offset+8 > int64(len(data)) {
			return 0, false
		}
		actual = binary.NativeEndian.Uint64(data[offset : offset+8])
	case "long", "belong", "ubelong":
		if offset+4 > int64(len(data)) {
			return 0, false
		}
		actual = uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
	case "lequad", "ulequad":
		if offset+8 > int64(len(data)) {
			return 0, false
		}
		actual = binary.LittleEndian.Uint64(data[offset : offset+8])
	case "quad", "bequad", "ubequad":
		if offset+8 > int64(len(data)) {
			return 0, false
		}
		actual = binary.BigEndian.Uint64(data[offset : offset+8])
	default:
		return 0, false
	}
	if r.HasMask {
		actual &= r.Mask
	}
	return applyTypeOp(actual, r), true
}

func pstringPayload(data []byte, r *Rule, offset int64) (string, bool) {
	if offset < 0 || offset >= int64(len(data)) {
		return "", false
	}

	var strLen int
	var headerLen int64
	switch r.PStringLengthType {
	case "h":
		if offset+2 > int64(len(data)) {
			return "", false
		}
		strLen = int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		headerLen = 2
	case "H":
		if offset+2 > int64(len(data)) {
			return "", false
		}
		strLen = int(binary.BigEndian.Uint16(data[offset : offset+2]))
		headerLen = 2
	case "l":
		if offset+4 > int64(len(data)) {
			return "", false
		}
		strLen = int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		headerLen = 4
	case "L":
		if offset+4 > int64(len(data)) {
			return "", false
		}
		strLen = int(binary.BigEndian.Uint32(data[offset : offset+4]))
		headerLen = 4
	default:
		strLen = int(data[offset])
		headerLen = 1
	}

	dataStart := offset + headerLen
	if dataStart > int64(len(data)) {
		return "", false
	}
	if strLen > len(data)-int(dataStart) {
		strLen = len(data) - int(dataStart)
	}
	if strLen < 0 {
		return "", false
	}
	return string(data[dataStart : dataStart+int64(strLen)]), true
}

func readCString(data []byte, offset int64, max int) string {
	if offset < 0 || offset >= int64(len(data)) || max <= 0 {
		return ""
	}
	end := offset
	limit := offset + int64(max)
	if limit > int64(len(data)) {
		limit = int64(len(data))
	}
	for end < limit && data[end] != 0 && data[end] != '\n' && data[end] != '\r' {
		end++
	}
	return string(data[offset:end])
}

func readUTF16(data []byte, offset int64, order binary.ByteOrder) string {
	if offset < 0 || offset+2 > int64(len(data)) {
		return ""
	}
	var b strings.Builder
	for offset+2 <= int64(len(data)) && b.Len() < 256 {
		u := order.Uint16(data[offset : offset+2])
		offset += 2
		if u == 0 {
			break
		}
		b.WriteRune(rune(u))
	}
	return b.String()
}

// compare handles the operators: =, !, >, <, &, ^
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
		return (actual & expected) == expected
	case "^":
		return (actual & expected) != expected
	default:
		return actual == expected
	}
}

// castToUint64 safely converts r.Value (uint8, uint16, uint32, uint64, int, int32, int64) to uint64
func castToUint64(v any) uint64 {
	switch val := v.(type) {
	case uint64:
		return val // Already a uint64, no cast needed!
	case uint32:
		return uint64(val)
	case uint16:
		return uint64(val)
	case uint8:
		return uint64(val)
	// prevent cast to 0 value by casting first
	case int:
		return uint64(int64(val)) // Zero-extend the entire value to 64 bits
	case int32:
		return uint64(uint32(val)) // Truncate/zero-extend to 64 bits
	case int64:
		return uint64(val) // Zero-extend the entire value to 64 bits
	default:
		return 0
	}
}
