package parser

import (
	"strings"
	"testing"
)

func TestParser_Parse(t *testing.T) {
	// Simulate a snippet of a real magic file
	input := `
# This is a comment
0	string	%PDF-	PDF document
!:mime	application/pdf

0	string	PK	Zip archive
!:mime	application/zip
>4	belong	0x0304	Local file header
`

	p := NewParser()
	err := p.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// We expect 3 rules total (PDF, Zip, and the Nested Header)
	// The !:mime lines should not count as separate rules.
	if len(p.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(p.Rules))
	}

	// Check if PDF rule got its MIME
	if p.Rules[0].Message != "PDF document" || p.Rules[0].Mime != "application/pdf" {
		t.Errorf("PDF rule mapping failed: %+v", p.Rules[0])
	}

	// Check if Zip rule got its MIME
	if p.Rules[1].Mime != "application/zip" {
		t.Errorf("Zip MIME mapping failed: %+v", p.Rules[1])
	}

	// Check if the nested rule (Level 1) was parsed correctly
	if p.Rules[2].Level != 1 || p.Rules[2].Offset != 4 {
		t.Errorf("Nested rule parsing failed: %+v", p.Rules[2])
	}
}
