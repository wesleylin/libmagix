package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDirectory(t *testing.T) {
	// 1. Create a temporary directory for our mock magic files
	tmpDir := t.TempDir()

	// 2. Create mock magic file 1: PDF
	pdfContent := "0\tstring\t%PDF-\tPDF document\n!:mime\tapplication/pdf\n"
	err := os.WriteFile(filepath.Join(tmpDir, "pdf"), []byte(pdfContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Create mock magic file 2: ZIP (with a child rule)
	zipContent := "0\tstring\tPK\tZip archive\n" +
		"!:mime\tapplication/zip\n" +
		">4\tbelong\t0x0304\tLocal file header\n"
	err = os.WriteFile(filepath.Join(tmpDir, "archive"), []byte(zipContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Create a file that should be ignored (starts with a dot)
	err = os.WriteFile(filepath.Join(tmpDir, ".ignored"), []byte("should not be parsed"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Run the Loader
	rules, err := LoadDirectory(tmpDir)
	if err != nil {
		t.Fatalf("LoadDirectory failed: %v", err)
	}

	// 6. Verify the results
	// We expect 2 Root Rules (PDF and Zip)
	if len(rules) != 2 {
		t.Errorf("expected 2 root rules, got %d", len(rules))
	}

	// Verify that children were loaded correctly inside the Zip rule
	foundChild := false
	for _, r := range rules {
		if r.Value == "PK" && len(r.Children) > 0 {
			foundChild = true
			if r.Children[0].Message != "Local file header" {
				t.Errorf("child message mismatch: %s", r.Children[0].Message)
			}
		}
	}

	if !foundChild {
		t.Error("failed to find Zip rule with children")
	}
}
