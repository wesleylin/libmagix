package libmagix_test

import (
	"testing"

	"github.com/wesleylin/libmagix"
	"github.com/wesleylin/libmagix/internal/parser"
)

func TestMatchTree(t *testing.T) {
	// 1. Manually construct a rule tree for testing
	// Level 0: ZIP archive
	//   Level 1: DOCX (specifically looks for 'word/' inside the zip structure)
	rules := []parser.Rule{
		{
			Level:    0,
			Offset:   0,
			Type:     "string",
			Value:    "PK",
			ValueRaw: []byte("PK"),
			Message:  "Zip archive",
			Mime:     "application/zip",
			Children: []parser.Rule{
				{
					Level:    1,
					Offset:   30, // Random offset for example
					Type:     "string",
					Value:    "word/",
					ValueRaw: []byte("word/"),
					Message:  "Microsoft Word",
					Mime:     "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
				},
			},
		},
		{
			Level:    0,
			Offset:   0,
			Type:     "string",
			Value:    "%PDF-",
			ValueRaw: []byte("%PDF-"),
			Message:  "PDF document",
			Mime:     "application/pdf",
		},
	}

	tests := []struct {
		name        string
		data        []byte
		expectedMsg string
	}{
		{
			name:        "Match Root Only (PDF)",
			data:        []byte("%PDF-1.4 header contents"),
			expectedMsg: "PDF document",
		},
		{
			name:        "Match Parent Only (Generic Zip)",
			data:        []byte("PK\x03\x04 and some other random bytes"),
			expectedMsg: "Zip archive",
		},
		{
			name: "Match Deepest Child (DOCX)",
			// Create a buffer that has PK at 0 and 'word/' at 30
			data: func() []byte {
				b := make([]byte, 50)
				copy(b[0:], "PK")
				copy(b[30:], "word/")
				return b
			}(),
			expectedMsg: "Microsoft Word",
		},
		{
			name:        "No Match",
			data:        []byte("Just some plain text"),
			expectedMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := libmagix.MatchTree(tt.data, rules)

			if tt.expectedMsg == "" {
				if got != nil {
					t.Errorf("Expected nil match, got %v", got.Message)
				}
				return
			}

			if got == nil {
				t.Fatalf("Expected match %q, got nil", tt.expectedMsg)
			}

			if got.Message != tt.expectedMsg {
				t.Errorf("MatchTree() Message = %v, want %v", got.Message, tt.expectedMsg)
			}
		})
	}
}
