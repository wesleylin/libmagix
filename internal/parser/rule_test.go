package parser

import (
	"encoding/binary"
	"testing"
)

func TestRule_Match(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
		data []byte
		want bool
	}{
		{
			name: "MatchAny (always true if in bounds)",
			rule: Rule{Offset: 0, MatchAny: true},
			data: []byte("anything"),
			want: true,
		},
		{
			name: "Little Endian uint32 match",
			rule: Rule{Offset: 0, Type: "lelong", Value: uint32(0x12345678), Operator: "="},
			data: []byte{0x78, 0x56, 0x34, 0x12},
			want: true,
		},
		{
			name: "Greater than match",
			rule: Rule{Offset: 0, Type: "byte", Value: uint8(10), Operator: ">"},
			data: []byte{20},
			want: true,
		},
		{
			name: "Less than match",
			rule: Rule{Offset: 0, Type: "byte", Value: uint8(10), Operator: "<"},
			data: []byte{5},
			want: true,
		},
		{
			name: "Bitmasking (has bit 0x80)",
			rule: Rule{Offset: 0, Type: "byte", Mask: 0x80, HasMask: true, Value: uint8(0x80), Operator: "="},
			data: []byte{0x81},
			want: true,
		},
		{
			name: "Bitwise AND operator (all bits set)",
			rule: Rule{Offset: 0, Type: "byte", Value: uint8(0x03), Operator: "&"},
			data: []byte{0x07}, // 0111 & 0011 == 0011
			want: true,
		},
		{
			name: "Bitwise NOT operator (bit NOT set)",
			rule: Rule{Offset: 0, Type: "byte", Value: uint8(0x80), Operator: "^"},
			data: []byte{0x7F}, // 0111 & 1000 == 0
			want: true,
		},
		{
			name: "Invalid value type in rule (fails cast)",
			rule: Rule{Offset: 0, Type: "string", Value: 123},
			data: []byte("123"),
			want: false,
		},
		{
			name: "Search match found",
			rule: Rule{Offset: 0, Type: "search", SearchRange: 10, Value: "FOUND"},
			data: []byte("---FOUND---"),
			want: true,
		},
		{
			name: "Search match NOT found (out of range)",
			rule: Rule{Offset: 0, Type: "search", SearchRange: 3, Value: "FOUND"},
			data: []byte("---FOUND---"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := tt.rule.Match(tt.data, 0, false); got != tt.want {
				t.Errorf("Rule.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRule_MatchByte(t *testing.T) {
	tests := []struct {
		name     string
		rule     Rule
		input    []byte
		expected bool
	}{
		{
			name: "Exact match at offset 0",
			rule: Rule{
				Offset: 0,
				Type:   "string",
				Value:  []byte("GIF89a"),
			},
			input:    []byte("GIF89a image data here"),
			expected: true,
		},
		{
			name: "Binary match (PNG header)",
			rule: Rule{
				Offset: 0,
				Type:   "string",
				Value:  []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
			},
			input:    []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00},
			expected: true,
		},
		{
			name: "Match at non-zero offset",
			rule: Rule{
				Offset: 4,
				Type:   "string",
				Value:  []byte("test"),
			},
			input:    []byte("____test_data"),
			expected: true,
		},
		{
			name: "Mismatch in data",
			rule: Rule{
				Offset:   0,
				Type:     "string",
				Value:    []byte("GIF89a"),
				ValueRaw: []byte("GIF89a"),
			},
			input:    []byte("JPEG image data"),
			expected: false,
		},
		{
			name: "Input data too short for offset",
			rule: Rule{
				Offset:   10,
				Type:     "string",
				Value:    []byte("tiny"),
				ValueRaw: []byte("tiny"),
			},
			input:    []byte("short"),
			expected: false,
		},
		{
			name: "Input data too short for signature length",
			rule: Rule{
				Offset:   0,
				Type:     "string",
				Value:    []byte("LONG_SIGNATURE"),
				ValueRaw: []byte("LONG_SIGNATURE"),
			},
			input:    []byte("SHORT"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rule.MatchByte(tt.input)
			if got != tt.expected {
				t.Errorf("MatchByte() = %v, want %v for input %v", got, tt.expected, tt.input)
			}
		})
	}
}

func TestRule_Match_PString(t *testing.T) {
	tests := []struct {
		name       string
		rule       Rule
		data       []byte
		wantMatch  bool
		wantOffset int64
	}{
		{
			name: "pstring/B - byte length prefix",
			rule: Rule{
				Offset:            0,
				Type:              "pstring",
				PStringLengthType: "B",
				Value:             "hello",
			},
			data:       []byte{0x05, 'h', 'e', 'l', 'l', 'o', 'w'},
			wantMatch:  true,
			wantOffset: 6,
		},
		{
			name: "pstring/h - 2-byte LE length prefix",
			rule: Rule{
				Offset:            0,
				Type:              "pstring",
				PStringLengthType: "h",
				Value:             "world",
			},
			data:       []byte{0x05, 0x00, 'w', 'o', 'r', 'l', 'd'},
			wantMatch:  true,
			wantOffset: 7,
		},
		{
			name: "pstring/H - 2-byte BE length prefix",
			rule: Rule{
				Offset:            0,
				Type:              "pstring",
				PStringLengthType: "H",
				Value:             "world",
			},
			data:       []byte{0x00, 0x05, 'w', 'o', 'r', 'l', 'd'},
			wantMatch:  true,
			wantOffset: 7,
		},
		{
			name: "pstring/l - 4-byte LE length prefix",
			rule: Rule{
				Offset:            0,
				Type:              "pstring",
				PStringLengthType: "l",
				Value:             "long",
			},
			data:       []byte{0x04, 0x00, 0x00, 0x00, 'l', 'o', 'n', 'g'},
			wantMatch:  true,
			wantOffset: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotOffset := tt.rule.Match(tt.data, 0, false)
			if gotMatch != tt.wantMatch || gotOffset != tt.wantOffset {
				t.Errorf("Match() = (%v, %v), want (%v, %v)", gotMatch, gotOffset, tt.wantMatch, tt.wantOffset)
			}
		})
	}
}

func TestRule_Match_UTF16(t *testing.T) {
	tests := []struct {
		name       string
		rule       Rule
		data       []byte
		wantMatch  bool
		wantOffset int64
	}{
		{
			name: "lestring16 match",
			rule: Rule{
				Offset: 0,
				Type:   "lestring16",
				Value:  "ABC",
			},
			data:       []byte{'A', 0x00, 'B', 0x00, 'C', 0x00},
			wantMatch:  true,
			wantOffset: 6,
		},
		{
			name: "bestring16 match",
			rule: Rule{
				Offset: 0,
				Type:   "bestring16",
				Value:  "ABC",
			},
			data:       []byte{0x00, 'A', 0x00, 'B', 0x00, 'C'},
			wantMatch:  true,
			wantOffset: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotOffset := tt.rule.Match(tt.data, 0, false)
			if gotMatch != tt.wantMatch || gotOffset != tt.wantOffset {
				t.Errorf("Match() = (%v, %v), want (%v, %v)", gotMatch, gotOffset, tt.wantMatch, tt.wantOffset)
			}
		})
	}
}

func TestRule_ResolveOffset_IndirectAdjustment(t *testing.T) {
	// Equivalent to: (2.s+11)
	rule := Rule{
		Offset:            0,
		IsIndirect:        true,
		PointerOffset:     2,
		PointerType:       "s", // little-endian short
		PointerAdd:        0,
		PointerAdjustment: 11,
	}

	data := make([]byte, 20)
	binary.LittleEndian.PutUint16(data[2:4], 5) // Value at offset 2 is 5

	gotOffset, ok := rule.resolveOffset(data, 0, false)
	if !ok {
		t.Fatal("resolveOffset failed")
	}
	if gotOffset != 16 {
		t.Errorf("resolveOffset() = %v, want 16", gotOffset)
	}
}

func TestRule_ResolveOffset_IndirectMultiply(t *testing.T) {
	rule := Rule{
		IsIndirect:        true,
		PointerOffset:     48,
		PointerType:       "l",
		PointerOp:         "*",
		PointerAdjustment: 4096,
	}

	data := make([]byte, 52)
	binary.LittleEndian.PutUint32(data[48:52], 3)

	gotOffset, ok := rule.resolveOffset(data, 0, false)
	if !ok {
		t.Fatal("resolveOffset failed")
	}
	if gotOffset != 3*4096 {
		t.Errorf("resolveOffset() = %v, want %v", gotOffset, 3*4096)
	}
}

func TestRule_SearchRangeIncludesPattern(t *testing.T) {
	rule := Rule{Type: "search", SearchRange: 1, Value: "P2", Operator: "="}
	got, off := rule.Match([]byte("P2\n2 2\n"), 0, false)
	if !got || off != 2 {
		t.Fatalf("search/1 = %v, %d; want match at 2", got, off)
	}
}

func TestRule_PStringAnyStopsAtNUL(t *testing.T) {
	// Length includes the trailing NUL. 'x' leaves the offset on that NUL.
	data := []byte{0x00, 0x05, 'a', 'b', 'c', 0, 'b'}
	rule := Rule{Type: "pstring", PStringLengthType: "H", MatchAny: true, Operator: "x"}
	got, off := rule.Match(data, 0, false)
	if !got || off != 5 {
		t.Fatalf("pstring x = %v, %d; want 5", got, off)
	}
}

func TestRule_GUIDAndDateShift(t *testing.T) {
	guid, err := ParseLine("0\tguid\tC1C41626-504C-4092-ACA9-41F936934328\tEFI")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28}
	if ok, _ := guid.Match(data, 0, false); !ok {
		t.Fatal("guid did not match")
	}

	shifted, err := ParseLine("0\tleldate+631065600\tx")
	if err != nil {
		t.Fatal(err)
	}
	if shifted.TypeOp != "+" || shifted.TypeOpArg != 631065600 {
		t.Fatalf("type op = %q %d", shifted.TypeOp, shifted.TypeOpArg)
	}
}

func TestRule_ResolveOffset_RelativeIndirect(t *testing.T) {
	// OpenPGP v2 header: CTB, 2-byte length 0x008d, version.
	// The use is at the body (offset 3). (&-2.S) reads the length and
	// lands on the next packet at 3+141 = 144.
	data := []byte{0x99, 0x00, 0x8d, 0x02}
	rule := Rule{
		IsIndirect:      true,
		IsRelative:      true,
		PointerRelative: true,
		PointerOffset:   -2,
		PointerType:     "S",
	}
	got, ok := rule.resolveOffset(data, 3, true)
	if !ok || got != 144 {
		t.Fatalf("resolveOffset() = %v, %d; want 144", ok, got)
	}

	// (&-1.B) from the byte after a 1-byte length header.
	one := []byte{0x98, 34, 0x02}
	byteRule := Rule{
		IsIndirect:      true,
		IsRelative:      true,
		PointerRelative: true,
		PointerOffset:   -1,
		PointerType:     "B",
	}
	got, ok = byteRule.resolveOffset(one, 2, true)
	if !ok || got != 36 {
		t.Fatalf("byte jump = %v, %d; want 36", ok, got)
	}
}

func TestRule_ResolveOffset_FromEnd(t *testing.T) {
	// ZIP end-of-central-directory is 22 bytes before EOF. (-6.l) reads the
	// central-directory offset stored 6 bytes before EOF.
	data := make([]byte, 40)
	data[18] = 7                                 // len-22
	binary.LittleEndian.PutUint32(data[34:], 12) // len-6
	plain := Rule{Offset: -22}
	got, ok := plain.resolveOffset(data, 0, false)
	if !ok || got != 18 {
		t.Fatalf("from end = %v, %d; want 18", ok, got)
	}
	indir := Rule{
		IsIndirect:    true,
		PointerOffset: -6,
		PointerType:   "l",
	}
	got, ok = indir.resolveOffset(data, 0, false)
	if !ok || got != 12 {
		t.Fatalf("indirect from end = %v, %d; want 12", ok, got)
	}
}
