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
			name: "Exact string match at start",
			rule: Rule{Offset: 0, Type: "string", Value: "%PDF-"},
			data: []byte("%PDF-1.4\n%âãÏÓ"),
			want: true,
		},
		{
			name: "String match at offset",
			rule: Rule{Offset: 2, Type: "string", Value: "PNG"},
			data: []byte("\x89HPNG\r\n\x1a\n"),
			want: true,
		},
		{
			name: "String mismatch",
			rule: Rule{Offset: 0, Type: "string", Value: "GIF"},
			data: []byte("%PDF-1.4"),
			want: false,
		},
		{
			name: "Offset out of bounds",
			rule: Rule{Offset: 100, Type: "string", Value: "test"},
			data: []byte("short file"),
			want: false,
		},
		{
			name: "Empty data",
			rule: Rule{Offset: 0, Type: "string", Value: "test"},
			data: []byte{},
			want: false,
		},
		{
			name: "Invalid value type in rule",
			rule: Rule{Offset: 0, Type: "string", Value: 123}, // Value should be string
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
