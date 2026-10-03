package parser

import (
	"fmt"
	"log/slog"
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
	p := NewParser(nil)
	rules, err := p.LoadDirectory(tmpDir)
	if err != nil {
		t.Fatalf("LoadDirectory failed: %v", err)
	}

	// 6. Verify the results
	// We expect 2 Root Rules (PDF and Zip)
	if len(rules) != 2 {
		for _, r := range rules {
			fmt.Printf("Rule: %+v\n", r)
		}

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

func TestAllowlistSkipsUnlistedFiles(t *testing.T) {
	root := t.TempDir()
	magdir := filepath.Join(root, "upstream", "Magdir")
	if err := os.MkdirAll(magdir, 0755); err != nil {
		t.Fatal(err)
	}
	pdf := "0\tstring\t%PDF-\tPDF document\n"
	if err := os.WriteFile(filepath.Join(magdir, "pdf"), []byte(pdf), 0644); err != nil {
		t.Fatal(err)
	}
	// Opened, this file fails to parse. The allowlist must not open it.
	if err := os.WriteFile(filepath.Join(magdir, "images"), []byte("not a magic line\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "allowlist"), []byte("# enabled\npdf\n"), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewParser(slog.New(slog.DiscardHandler))
	rules, err := p.LoadDirectory(magdir)
	if err != nil {
		t.Fatalf("LoadDirectory: %v", err)
	}
	if len(rules) != 1 || rules[0].Message != "PDF document" {
		t.Fatalf("rules = %+v, want the pdf rule only", rules)
	}
}

func TestAllowlistParseError(t *testing.T) {
	root := t.TempDir()
	magdir := filepath.Join(root, "upstream", "Magdir")
	if err := os.MkdirAll(magdir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(magdir, "pdf"), []byte("not a magic line\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "allowlist"), []byte("pdf\n"), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewParser(slog.New(slog.DiscardHandler))
	if _, err := p.LoadDirectory(magdir); err == nil {
		t.Fatal("expected parse error for an allowlisted file")
	}
}

func TestVendoredAllowlistParses(t *testing.T) {
	p := NewParser(slog.New(slog.DiscardHandler))
	rules, err := p.LoadDirectory("../../magic/upstream/Magdir")
	if err != nil {
		t.Fatalf("LoadDirectory: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("allowlist produced no rules")
	}
}

func TestBundledMagicParses(t *testing.T) {
	matches, err := filepath.Glob("../../magic/Magdir/*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no bundled magic files found")
	}
	p := NewParser(slog.New(slog.DiscardHandler))
	for _, path := range matches {
		if _, err := p.LoadFile(path); err != nil {
			t.Errorf("%s: %v", filepath.Base(path), err)
		}
	}
}
