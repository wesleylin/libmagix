package libmagix

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// jsonMessage is file's file_is_json check. It runs before magic.
// A buffer that is one JSON array or object is "JSON text data".
// A second value of the same kind is "New Line Delimited JSON text data".
func jsonMessage(data []byte) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	p := 0
	var st [6]int
	switch jsonParse(data, &p, &st, 0) {
	case 1:
		return "JSON text data", true
	case 2:
		return "New Line Delimited JSON text data", true
	default:
		return "", false
	}
}

func jsonSpace(c byte) bool {
	return c == ' ' || c == '\n' || c == '\r' || c == '\t'
}

func jsonSkip(data []byte, p int) int {
	for p < len(data) && jsonSpace(data[p]) {
		p++
	}
	return p
}

func jsonParse(data []byte, p *int, st *[6]int, lvl int) int {
	ouc := jsonSkip(data, *p)
	uc := ouc
	if uc == len(data) {
		*p = uc
		return 0
	}
	if lvl > 500 {
		return 0
	}
	var rv int
	var t int
	switch data[uc] {
	case '"':
		uc++
		rv = jsonString(data, &uc)
		t = 4
	case '[':
		uc++
		rv = jsonArray(data, &uc, st, lvl+1)
		t = 0
	case '{':
		uc++
		rv = jsonObject(data, &uc, st, lvl+1)
		t = 3
	case 't':
		uc++
		rv = jsonConst(data, &uc, "true")
		t = 1
	case 'f':
		uc++
		rv = jsonConst(data, &uc, "false")
		t = 1
	case 'n':
		uc++
		rv = jsonConst(data, &uc, "null")
		t = 1
	default:
		rv = jsonNumber(data, &uc)
		t = 2
	}
	if rv != 0 {
		st[t]++
	}
	uc = jsonSkip(data, uc)
	*p = uc
	if lvl != 0 {
		return rv
	}
	if rv == 0 {
		return 0
	}
	if uc == len(data) {
		if st[0] != 0 || st[3] != 0 {
			return 1
		}
		return 0
	}
	if ouc < len(data) && data[ouc] == data[uc] && jsonParse(data, &uc, st, 1) != 0 {
		if st[0] != 0 || st[3] != 0 {
			return 2
		}
	}
	return 0
}

func jsonString(data []byte, p *int) int {
	uc := *p
	for uc < len(data) {
		c := data[uc]
		uc++
		switch c {
		case 0:
			*p = uc
			return 0
		case '\\':
			if uc == len(data) {
				*p = uc
				return 0
			}
			e := data[uc]
			uc++
			switch e {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				continue
			case 'u':
				if len(data)-uc < 4 {
					*p = len(data)
					return 0
				}
				for i := 0; i < 4; i++ {
					if !jsonHex(data[uc]) {
						*p = uc
						return 0
					}
					uc++
				}
				continue
			default:
				*p = uc
				return 0
			}
		case '"':
			*p = uc
			return 1
		}
	}
	*p = uc
	return 0
}

func jsonHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func jsonArray(data []byte, p *int, st *[6]int, lvl int) int {
	uc := *p
	for uc < len(data) {
		uc = jsonSkip(data, uc)
		if uc == len(data) {
			break
		}
		if data[uc] == ']' {
			st[5]++
			*p = uc + 1
			return 1
		}
		if jsonParse(data, &uc, st, lvl) == 0 {
			*p = uc
			return 0
		}
		if uc == len(data) {
			break
		}
		switch data[uc] {
		case ',':
			uc++
			continue
		case ']':
			st[5]++
			*p = uc + 1
			return 1
		default:
			*p = uc
			return 0
		}
	}
	*p = uc
	return 0
}

func jsonObject(data []byte, p *int, st *[6]int, lvl int) int {
	uc := *p
	for uc < len(data) {
		uc = jsonSkip(data, uc)
		if uc == len(data) {
			break
		}
		if data[uc] == '}' {
			uc++
			*p = uc
			return 1
		}
		if data[uc] != '"' {
			*p = uc
			return 0
		}
		uc++
		if jsonString(data, &uc) == 0 {
			*p = uc
			return 0
		}
		uc = jsonSkip(data, uc)
		if uc == len(data) || data[uc] != ':' {
			*p = uc
			return 0
		}
		uc++
		if jsonParse(data, &uc, st, lvl) == 0 {
			*p = uc
			return 0
		}
		if uc == len(data) {
			break
		}
		switch data[uc] {
		case ',':
			uc++
			continue
		case '}':
			uc++
			*p = uc
			return 1
		default:
			*p = uc
			return 0
		}
	}
	*p = uc
	return 0
}

func jsonConst(data []byte, p *int, lit string) int {
	rest := lit[1:]
	if *p+len(rest) > len(data) || string(data[*p:*p+len(rest)]) != rest {
		if *p+len(rest) > len(data) {
			*p = len(data)
		}
		return 0
	}
	*p += len(rest)
	return 1
}

func jsonNumber(data []byte, p *int) int {
	uc := *p
	if uc == len(data) {
		return 0
	}
	if data[uc] == '-' {
		uc++
	}
	got := false
	for uc < len(data) && data[uc] >= '0' && data[uc] <= '9' {
		got = true
		uc++
	}
	if uc < len(data) && data[uc] == '.' {
		uc++
		for uc < len(data) && data[uc] >= '0' && data[uc] <= '9' {
			got = true
			uc++
		}
	}
	if got && uc < len(data) && (data[uc] == 'e' || data[uc] == 'E') {
		uc++
		got = false
		if uc < len(data) && (data[uc] == '+' || data[uc] == '-') {
			uc++
		}
		for uc < len(data) && data[uc] >= '0' && data[uc] <= '9' {
			got = true
			uc++
		}
	}
	*p = uc
	if got {
		return 1
	}
	return 0
}

// textView is the buffer the text pass matches, plus the encoding name
// file prints. Binary buffers return ok false.
func textView(data []byte) (view []byte, code string, ok bool) {
	if looksASCII(data) {
		return data, "ASCII", true
	}
	if decoded, code, ok := decodeUTF16BOM(data); ok {
		return decoded, code, true
	}
	return nil, "", false
}

func looksASCII(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, c := range data {
		switch c {
		case 0x07, 0x08, '\t', '\n', '\f', '\r', 0x1b, 0x85:
			continue
		}
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

func decodeUTF16BOM(data []byte) ([]byte, string, bool) {
	if len(data) < 2 {
		return nil, "", false
	}
	var order binary.ByteOrder
	var code string
	switch {
	case data[0] == 0xff && data[1] == 0xfe:
		order = binary.LittleEndian
		code = "Unicode text, UTF-16, little-endian"
	case data[0] == 0xfe && data[1] == 0xff:
		order = binary.BigEndian
		code = "Unicode text, UTF-16, big-endian"
	default:
		return nil, "", false
	}
	body := data[2:]
	if len(body)%2 != 0 {
		body = body[:len(body)-1]
	}
	units := make([]uint16, len(body)/2)
	for i := range units {
		units[i] = order.Uint16(body[i*2:])
	}
	return []byte(string(utf16.Decode(units))), code, true
}

// appendTextTail adds file's ascmagic encoding phrase.
// A description that ends in " text executable" becomes ", ASCII text executable".
func appendTextTail(msg, code string, view []byte) string {
	executable := false
	if msg != "" {
		switch {
		case strings.HasSuffix(msg, " text"):
			msg = strings.TrimSuffix(msg, " text") + ", "
		case strings.HasSuffix(msg, " text executable"):
			msg = strings.TrimSuffix(msg, " text executable") + ", "
			executable = true
		default:
			msg += ", "
		}
	}
	msg += code + " text"
	if executable {
		msg += " executable"
	}
	msg += lineNote(view)
	return msg
}

func lineNote(data []byte) string {
	var nCRLF, nCR, nLF, nNEL, line, longest int
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c == '\n' || c == '\r' || c == 0x85 {
			if line > longest {
				longest = line
			}
			line = 0
		} else {
			line++
		}
		switch c {
		case '\r':
			if i+1 < len(data) && data[i+1] == '\n' {
				nCRLF++
				i++
			} else {
				nCR++
			}
		case '\n':
			nLF++
		case 0x85:
			nNEL++
		}
	}
	if line > longest {
		longest = line
	}
	var b strings.Builder
	if longest > 300 {
		fmt.Fprintf(&b, ", with very long lines (%d)", longest)
	}
	if nCRLF == 0 && nCR == 0 && nNEL == 0 && nLF == 0 {
		b.WriteString(", with no line terminators")
		return b.String()
	}
	if nCRLF == 0 && nCR == 0 && nNEL == 0 {
		return b.String()
	}
	b.WriteString(", with")
	wrote := false
	writeKind := func(n int, name string) {
		if n == 0 {
			return
		}
		if wrote {
			b.WriteByte(',')
		}
		b.WriteByte(' ')
		b.WriteString(name)
		wrote = true
	}
	writeKind(nCRLF, "CRLF")
	writeKind(nCR, "CR")
	writeKind(nLF, "LF")
	writeKind(nNEL, "NEL")
	b.WriteString(" line terminators")
	return b.String()
}

// escapeControls turns the bytes file's file_getbuffer prints as octal.
// A continue-mode newline becomes the four characters \012.
func escapeControls(s string) string {
	needs := false
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "\\%03o", c)
	}
	return b.String()
}
