package parser

import (
	"reflect"
	"testing"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *Rule
		wantErr bool
	}{
		{
			name:  "Simple PDF check",
			input: "0\tstring\t%PDF-\tPDF document",
			want: &Rule{
				Level:    0,
				Offset:   0,
				Type:     "string",
				Value:    "%PDF-",
				ValueRaw: []byte("%PDF-"),
				Message:  "PDF document",
			},
			wantErr: false,
		},
		{
			name:  "Nested level 1",
			input: ">5\tstring\t1.4\tversion 1.4",
			want: &Rule{
				Level:    1,
				Offset:   5,
				Type:     "string",
				Value:    "1.4",
				ValueRaw: []byte("1.4"),
				Message:  "version 1.4",
			},
			wantErr: false,
		},
		{
			name:    "Comment line",
			input:   "# this is a comment",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "Invalid offset",
			input:   "abc\tstring\tval\tmsg",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLine(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTypeAndMask(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantType    string
		wantMask    uint64
		wantHasMask bool
		wantErr     bool
	}{
		{"No Mask", "belong", "belong", 0, false, false},
		{"Hex Mask", "belong&0xFFFF", "belong", 0xFFFF, true, false},
		{"Decimal Mask", "lelong&255", "lelong", 255, true, false},
		{"Invalid Mask", "belong&invalid", "", 0, false, true},
		{"Empty Mask", "belong&", "", 0, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotMask, gotHasMask, err := parseTypeAndMask(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTypeAndMask() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotType != tt.wantType || gotMask != tt.wantMask || gotHasMask != tt.wantHasMask {
				t.Errorf("got (%s, %v, %v), want (%s, %v, %v)",
					gotType, gotMask, gotHasMask, tt.wantType, tt.wantMask, tt.wantHasMask)
			}
		})
	}
}

func TestParseOperator(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantOp  string
		wantVal string
	}{
		{"Explicit Equal", "=0x20", "=", "0x20"},
		{"Greater Than", ">10", ">", "10"},
		{"Not Equal", "!0", "!", "0"},
		{"Bitwise And", "&0xFF", "&", "0xFF"},
		{"Default Equal", "1234", "=", "1234"},
		{"Empty Value", ">", ">", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOp, gotVal := parseOperator(tt.input)
			if gotOp != tt.wantOp || gotVal != tt.wantVal {
				t.Errorf("got (%s, %s), want (%s, %s)", gotOp, gotVal, tt.wantOp, tt.wantVal)
			}
		})
	}
}
