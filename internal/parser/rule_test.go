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
			rule: Rule{Offset: 0, Type: "search", SearchRange: 5, Value: "FOUND"},
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
