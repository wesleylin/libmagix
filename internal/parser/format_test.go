package parser

import "testing"

func TestFormatMessage(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		typeName string
		value    any
		want     string
	}{
		{
			name:     "unsigned decimal",
			message:  `\b, %u object`,
			typeName: "ulelong",
			value:    uint64(1),
			want:     `\b, 1 object`,
		},
		{
			name:     "string precision",
			message:  "(%-.19s)",
			typeName: "string",
			value:    "abcdefghijklmnopqrstuvwxyz",
			want:     "(abcdefghijklmnopqrs)",
		},
		{
			name:     "literal percent",
			message:  "100%% done %u",
			typeName: "byte",
			value:    uint64(3),
			want:     "100% done 3",
		},
		{
			name:     "signed byte",
			message:  "delta %d",
			typeName: "byte",
			value:    uint64(255),
			want:     "delta -1",
		},
		{
			name:     "hex with prefix",
			message:  "id %#x",
			typeName: "uleshort",
			value:    uint64(0x2a),
			want:     "id 0x2a",
		},
		{
			name:     "nonprintable octal escape",
			message:  "name %s",
			typeName: "pstring",
			value:    "A\x01B",
			want:     `name A\001B`,
		},
		{
			name:     "no conversion",
			message:  "Zip archive data",
			typeName: "string",
			value:    "PK",
			want:     "Zip archive data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatMessage(tt.message, tt.typeName, tt.value)
			if got != tt.want {
				t.Errorf("FormatMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSplitNumericOp(t *testing.T) {
	tests := []struct {
		in   string
		base string
		op   string
		arg  uint64
	}{
		{"uleshort/256", "uleshort", "/", 256},
		{"ulelong%256", "ulelong", "%", 256},
		{"string/c", "string/c", "", 0},
		{"belong", "belong", "", 0},
	}
	for _, tt := range tests {
		base, op, arg := splitNumericOp(tt.in)
		if base != tt.base || op != tt.op || arg != tt.arg {
			t.Errorf("splitNumericOp(%q) = (%q, %q, %d), want (%q, %q, %d)",
				tt.in, base, op, arg, tt.base, tt.op, tt.arg)
		}
	}
}
