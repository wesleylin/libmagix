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
