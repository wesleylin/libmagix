package parser

import (
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.Match(tt.data); got != tt.want {
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
