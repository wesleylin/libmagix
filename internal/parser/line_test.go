package parser

import (
	"testing"

	"github.com/google/go-cmp/cmp"
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
				Operator: "=",
				Message:  "PDF document",
			},
			wantErr: false,
		},
		{
			name:  "ulelong check",
			input: "0\tulelong\t0x20\tBMP Windows 3.x",
			want: &Rule{
				Level:    0,
				Offset:   0,
				Type:     "ulelong",
				Value:    uint32(32),
				Operator: "=",
				Message:  "BMP Windows 3.x",
			},
			wantErr: false,
		},
		{
			name:  "Match any 'x' check",
			input: ">18\tulelong\tx\twidth unknown",
			want: &Rule{
				Level:    1,
				Offset:   18,
				Type:     "ulelong",
				Value:    nil,
				Operator: "=",
				Message:  "width unknown",
				MatchAny: true,
			},
			wantErr: false,
		},
		{
			name:  "ubyte check",
			input: "0\tubyte\t255\tmax byte",
			want: &Rule{
				Level:    0,
				Offset:   0,
				Type:     "ubyte",
				Value:    uint8(255),
				Operator: "=",
				Message:  "max byte",
			},
			wantErr: false,
		},
		{
			name:    "Invalid offset",
			input:   "abc\tstring\tval\tmsg",
			want:    nil,
			wantErr: true,
		},
		{
			name:  "pstring check",
			input: ">>>2\tpstring/h\tx\tmsg",
			want: &Rule{
				Level:             3,
				Offset:            2,
				Type:              "pstring",
				PStringLengthType: "h",
				MatchAny:          true,
				Operator:          "=",
				Message:           "msg",
			},
			wantErr: false,
		},
		{
			name:  "Indirect offset with adjustment",
			input: ">>>>(2.s+11)\tpstring/h\tx\tmsg",
			want: &Rule{
				Level:             4,
				Offset:            0,
				IsIndirect:        true,
				PointerOffset:     2,
				PointerType:       "s",
				PointerAdjustment: 11,
				Type:              "pstring",
				PStringLengthType: "h",
				MatchAny:          true,
				Operator:          "=",
				Message:           "msg",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLine(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ParseLine() mismatch (-want +got):\n%s", diff)
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
