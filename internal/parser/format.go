package parser

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// FormatMessage substitutes the matched value into a magic description.
// Descriptions follow printf: "%u", "%#x", "%.20s", and "%%".
func FormatMessage(message, typeName string, value any) string {
	if !strings.Contains(message, "%") {
		return message
	}

	var b strings.Builder
	for i := 0; i < len(message); i++ {
		if message[i] != '%' {
			b.WriteByte(message[i])
			continue
		}
		if i+1 < len(message) && message[i+1] == '%' {
			b.WriteByte('%')
			i++
			continue
		}
		spec, n := parseSpec(message[i:])
		if n == 0 {
			b.WriteByte('%')
			continue
		}
		b.WriteString(renderSpec(spec, typeName, value))
		i += n - 1
	}
	return b.String()
}

func parseSpec(s string) (string, int) {
	if len(s) < 2 || s[0] != '%' {
		return "", 0
	}
	i := 1
	for i < len(s) && strings.ContainsRune("-+ #0", rune(s[i])) {
		i++
	}
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i < len(s) && s[i] == '.' {
		i++
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	}
	for i < len(s) && strings.ContainsRune("hlLjzt", rune(s[i])) {
		i++
	}
	if i >= len(s) || !strings.ContainsRune("diouxXeEfFgGaAcsp", rune(s[i])) {
		return "", 0
	}
	return s[:i+1], i + 1
}

func renderSpec(spec, typeName string, value any) string {
	verb := spec[len(spec)-1]
	switch verb {
	case 's':
		if formatted, ok := formatTimestamp(typeName, value); ok {
			return formatString(spec, formatted)
		}
		return formatString(spec, coerceString(value))
	case 'c':
		n, ok := coerceUint(value)
		if !ok {
			return spec
		}
		return string([]byte{byte(n)})
	case 'd', 'i', 'u', 'x', 'X', 'o':
		rendered, ok := formatNumber(spec, typeName, value)
		if !ok {
			return spec
		}
		return rendered
	default:
		return spec
	}
}

func isTimestamp(typeName string) bool {
	switch typeName {
	case "date", "ldate", "bedate", "beldate", "ledate", "leldate", "medate", "meldate",
		"qdate", "lqdate", "beqdate", "beqldate", "leqdate", "leqldate":
		return true
	default:
		return false
	}
}

func isLocalTimestamp(typeName string) bool {
	switch typeName {
	case "ldate", "beldate", "leldate", "meldate", "lqdate", "beqldate", "leqldate":
		return true
	default:
		return false
	}
}

// formatTimestamp prints a Unix time the way file's asctime does.
// Types without an "l" are UTC. The "l" types are local time.
func formatTimestamp(typeName string, value any) (string, bool) {
	if !isTimestamp(typeName) {
		return "", false
	}
	n, ok := coerceUint(value)
	if !ok {
		return "", false
	}
	sec := int64(n)
	switch typeName {
	case "date", "ldate", "bedate", "beldate", "ledate", "leldate", "medate", "meldate":
		sec = int64(uint32(n))
	}
	when := time.Unix(sec, 0)
	if isLocalTimestamp(typeName) {
		when = when.In(time.Local)
	} else {
		when = when.UTC()
	}
	return when.Format("Mon Jan _2 15:04:05 2006"), true
}

func formatString(spec, s string) string {
	s = toPrintable(s)
	if prec, ok := specPrecision(spec); ok && prec >= 0 && len(s) > prec {
		s = s[:prec]
	}
	return s
}

func specPrecision(spec string) (int, bool) {
	dot := strings.IndexByte(spec, '.')
	if dot < 0 || dot+1 >= len(spec) {
		return 0, false
	}
	end := dot + 1
	for end < len(spec) && spec[end] >= '0' && spec[end] <= '9' {
		end++
	}
	if end == dot+1 {
		return 0, true
	}
	n, err := strconv.Atoi(spec[dot+1 : end])
	if err != nil {
		return 0, false
	}
	return n, true
}

func toPrintable(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "\\%03o", c)
		}
	}
	return b.String()
}

func formatNumber(spec, typeName string, value any) (string, bool) {
	n, ok := coerceUint(value)
	if !ok {
		return "", false
	}
	bits, unsigned := numericKind(typeName)
	verb := spec[len(spec)-1]
	gverb := verb
	var arg any
	if verb == 'd' || verb == 'i' {
		gverb = 'd'
		if unsigned {
			arg = maskUint(n, bits)
		} else {
			arg = signExtend(n, bits)
		}
	} else {
		if verb == 'u' {
			gverb = 'd'
		}
		arg = maskUint(n, bits)
	}
	if verb == 'x' || verb == 'X' {
		return formatHex(maskUint(n, bits), spec), true
	}
	body := spec[1 : len(spec)-1]
	body = strings.TrimRight(body, "hlLjzt")
	return fmt.Sprintf("%"+body+string(gverb), arg), true
}

// formatHex follows C printf for "%#08x": the width covers the 0x prefix,
// and a zero value does not get that prefix.
func formatHex(n uint64, spec string) string {
	verb := spec[len(spec)-1]
	body := strings.TrimRight(spec[1:len(spec)-1], "hlLjzt")
	alt := strings.Contains(body, "#")
	zeroPad := strings.Contains(body, "0") && !strings.Contains(body, "-")
	width, prec, hasPrec := 0, 0, false
	i := 0
	for i < len(body) && strings.ContainsRune("-+ #0", rune(body[i])) {
		i++
	}
	start := i
	for i < len(body) && body[i] >= '0' && body[i] <= '9' {
		width = width*10 + int(body[i]-'0')
		i++
	}
	if i == start {
		width = 0
	}
	if i < len(body) && body[i] == '.' {
		hasPrec = true
		i++
		for i < len(body) && body[i] >= '0' && body[i] <= '9' {
			prec = prec*10 + int(body[i]-'0')
			i++
		}
		zeroPad = false
	}
	digits := strconv.FormatUint(n, 16)
	if verb == 'X' {
		digits = strings.ToUpper(digits)
	}
	if hasPrec && prec > len(digits) {
		digits = strings.Repeat("0", prec-len(digits)) + digits
	}
	prefix := ""
	if alt && n != 0 {
		prefix = "0x"
		if verb == 'X' {
			prefix = "0X"
		}
	}
	if width > len(prefix)+len(digits) {
		pad := width - len(prefix) - len(digits)
		if zeroPad {
			digits = strings.Repeat("0", pad) + digits
		} else {
			return strings.Repeat(" ", pad) + prefix + digits
		}
	}
	return prefix + digits
}

func coerceString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case uint64:
		return strconv.FormatUint(v, 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func coerceUint(value any) (uint64, bool) {
	switch v := value.(type) {
	case uint64:
		return v, true
	case uint32:
		return uint64(v), true
	case uint16:
		return uint64(v), true
	case uint8:
		return uint64(v), true
	case int64:
		return uint64(v), true
	case int32:
		return uint64(uint32(v)), true
	case int:
		return uint64(v), true
	default:
		return 0, false
	}
}

func numericKind(typeName string) (bits int, unsigned bool) {
	switch typeName {
	case "byte":
		return 8, false
	case "ubyte":
		return 8, true
	case "short", "beshort", "leshort":
		return 16, false
	case "ushort", "ubeshort", "uleshort", "uint16":
		return 16, true
	case "long", "belong", "lelong":
		return 32, false
	case "ulong", "ubelong", "ulelong", "uint32":
		return 32, true
	case "quad", "bequad", "lequad":
		return 64, false
	case "uquad", "ubequad", "ulequad":
		return 64, true
	default:
		return 64, true
	}
}

func maskUint(v uint64, bits int) uint64 {
	if bits >= 64 {
		return v
	}
	return v & ((1 << bits) - 1)
}

func signExtend(v uint64, bits int) int64 {
	switch bits {
	case 8:
		return int64(int8(uint8(v)))
	case 16:
		return int64(int16(uint16(v)))
	case 32:
		return int64(int32(uint32(v)))
	default:
		return int64(v)
	}
}
