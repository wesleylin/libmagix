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
				Level:   0,
				Offset:  0,
				Type:    "string",
				Value:   "%PDF-",
				Message: "PDF document",
			},
			wantErr: false,
		},
		{
			name:  "Nested level 1",
			input: ">5\tstring\t1.4\tversion 1.4",
			want: &Rule{
				Level:   1,
				Offset:  5,
				Type:    "string",
				Value:   "1.4",
				Message: "version 1.4",
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
