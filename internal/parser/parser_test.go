package parser

import (
	"strings"
	"testing"
)

func TestParser_Parse(t *testing.T) {
	input := `
0	string	%PDF-	PDF document
!:mime	application/pdf

0	string	PK	Zip archive
!:mime	application/zip
>4	belong	0x0304	Local file header
`

	p := NewParser(nil)
	rules, err := p.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// 1. Check Root Rules (Should be 2: PDF and Zip)
	if len(rules) != 2 {
		t.Errorf("expected 2 root rules, got %d", len(rules))
	}

	// 2. Check PDF (RootRules[0])
	if rules[0].Mime != "application/pdf" {
		t.Errorf("PDF MIME failed: %s", rules[0].Mime)
	}

	// 3. Check Zip (RootRules[1])
	zipRule := rules[1]
	if zipRule.Mime != "application/zip" {
		t.Errorf("Zip MIME failed: %s", zipRule.Mime)
	}

	// 4. Check Zip's Child (The Local file header)
	if len(zipRule.Children) != 1 {
		t.Errorf("Expected Zip to have 1 child, got %d", len(zipRule.Children))
	} else {
		child := zipRule.Children[0]
		if child.Level != 1 || child.Message != "Local file header" {
			t.Errorf("Child rule mismatch: %+v", child)
		}
	}
}
