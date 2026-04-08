package libmagix_test

import (
	"encoding/binary"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/wesleylin/libmagix"
)

func TestGIFIdentification(t *testing.T) {
	// 1. Setup a logger that only shows errors unless we run with -v
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// 2. Initialize the engine using the public API
	// This points to our tiny test magic file
	engine, err := libmagix.New("magic/Magdir/basicGif", logger)
	if err != nil {
		t.Fatalf("Failed to initialize engine: %v", err)
	}

	// 3. Load the actual GIF bytes from testdata
	gifData, err := os.ReadFile("testdata/sample.gif")
	if err != nil {
		t.Fatalf("Failed to read test GIF: %v", err)
	}

	// 4. Run the identification
	got := engine.Identify(gifData)
	want := "GIF image data (89a)"

	// 5. Assert
	if got.Message != want {
		t.Errorf("Identify() = %q; want %q", got, want)
	}
}

func TestJavaIdentification(t *testing.T) {
	// 1. Initialize engine
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/java", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	// 2. Create fake Java class data (Cafe Babe)
	// 0xCAFEBABE = 3405691582
	javaData := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34}

	// 3. Identify
	got := engine.Identify(javaData)
	want := "Java class data"

	if got == nil {
		t.Fatal("Expected identification, got nil")
	}
	if got.Message != want {
		t.Errorf("Got %q, want %q", got.Message, want)
	}
}

func TestHighVersionIdentification(t *testing.T) {
	// 1. Setup Logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// 2. Create a temporary directory for this specific test
	tmpDir := t.TempDir()
	magicFilePath := filepath.Join(tmpDir, "version_check")

	// 3. Write the specific magic rule we want to test
	//    Rule: First byte must be greater than 10
	magicContent := "0\tbyte\t>10\tHigh Version Format\n"
	if err := os.WriteFile(magicFilePath, []byte(magicContent), 0644); err != nil {
		t.Fatalf("Failed to write mock magic file: %v", err)
	}

	// 4. Initialize the engine pointing to our temp file
	engine, err := libmagix.New(magicFilePath, logger)
	if err != nil {
		t.Fatalf("Failed to initialize engine: %v", err)
	}

	// 5. Test Case A: Should Match (Value 11 > 10)
	dataMatch := []byte{11, 0x00, 0x00}
	got := engine.Identify(dataMatch)
	want := "High Version Format"

	if got == nil {
		t.Fatal("Expected match for byte > 10, got nil")
	}
	if got.Message != want {
		t.Errorf("Identify() = %q; want %q", got.Message, want)
	}

	// 6. Test Case B: Should NOT Match (Value 10 is not > 10)
	dataNoMatch := []byte{10, 0x00, 0x00}
	gotNoMatch := engine.Identify(dataNoMatch)

	if gotNoMatch != nil {
		t.Errorf("Expected nil match for value 10, got %q", gotNoMatch.Message)
	}
}

func TestELFIdentification(t *testing.T) {
	// 1. Initialize engine
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/elf", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	// 2. Load the actual ELF bytes from testdata
	elfData, err := os.ReadFile("testdata/sample.elf")
	if err != nil {
		t.Fatalf("Failed to read test ELF: %v", err)
	}

	// 3. Identify
	got := engine.Identify(elfData)
	want := "ELF 64-bit executable"

	if got == nil {
		t.Fatal("Expected identification, got nil")
	}
	if got.Message != want {
		t.Errorf("Got %q, want %q", got.Message, want)
	}
}

func TestBMPIdentificationTemp(t *testing.T) {
	// 1. Initialize engine
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/bmp", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	// 2. Create fake BMP Windows 3.x header data
	// Offset 0: BM
	// Offset 14: 40 (lelong)
	bmpData := make([]byte, 54)
	copy(bmpData[0:2], "BM")
	binary.LittleEndian.PutUint32(bmpData[14:18], 40)

	// 3. Identify
	got := engine.Identify(bmpData)
	want := "PC bitmap Windows 3.x format"

	if got == nil {
		t.Fatal("Expected identification, got nil")
	}
	if got.Message != want {
		t.Errorf("Got %q, want %q", got.Message, want)
	}
}

func TestBMPIdentificationSample(t *testing.T) {
	// 1. Initialize engine
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/bmp", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	bmpData, err := os.ReadFile("testdata/blackbuck.bmp")
	if err != nil {
		t.Fatalf("Failed to read test BMP: %v", err)
	}

	// 3. Identify
	got := engine.Identify(bmpData)
	want := "PC bitmap Windows 3.x format"

	if got == nil {
		t.Fatal("Expected identification, got nil")
	}
	if got.Message != want {
		t.Errorf("Got %q, want %q", got.Message, want)
	}
}

func TestScriptIdentification(t *testing.T) {
	// 1. Initialize engine
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/script", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	// 2. Test sh
	shData, err := os.ReadFile("testdata/sample.sh")
	if err != nil {
		t.Fatalf("Failed to read sh sample: %v", err)
	}
	got := engine.Identify(shData)
	if got == nil || got.Message != "POSIX shell script" {
		t.Errorf("Identify(sh) = %v, want POSIX shell script", got)
	}

	// 3. Test bash
	bashData, err := os.ReadFile("testdata/sample.bash")
	if err != nil {
		t.Fatalf("Failed to read bash sample: %v", err)
	}
	got = engine.Identify(bashData)
	if got == nil || got.Message != "bash shell script" {
		t.Errorf("Identify(bash) = %v, want bash shell script", got)
	}
}

func TestPEIdentification(t *testing.T) {
	// 1. Initialize engine
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/pe", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	// 2. Create fake PE header data
	// Offset 0: MZ
	// Offset 0x3C: 0x40 (pointer to PE)
	// Offset 0x40: PE\0\0
	// Offset 0x44: 0x8664 (x86-64)
	peData := make([]byte, 256)
	copy(peData[0:2], "MZ")
	binary.LittleEndian.PutUint32(peData[0x3c:], 0x40)
	copy(peData[0x40:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(peData[0x44:], 0x8664)

	// 3. Identify
	got := engine.Identify(peData)
	want := "MS-DOS executable, PE executable, x86-64"

	if got == nil {
		t.Fatal("Expected identification, got nil")
	}
	if got.Message != want {
		t.Errorf("Got %q, want %q", got.Message, want)
	}
}

func TestTIFFIdentificationMock(t *testing.T) {
	// 1. Initialize engine
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/tiff", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	// 2. Test II (Little Endian)
	iiData := []byte{0x49, 0x49, 0x2A, 0x00}
	got := engine.Identify(iiData)
	if got == nil || got.Message != "TIFF image data, little-endian" {
		t.Errorf("Identify(II) = %v, want TIFF image data, little-endian", got)
	}

	// 3. Test MM (Big Endian)
	mmData := []byte{0x4D, 0x4D, 0x00, 0x2A}
	got = engine.Identify(mmData)
	if got == nil || got.Message != "TIFF image data, big-endian" {
		t.Errorf("Identify(MM) = %v, want TIFF image data, big-endian", got)
	}
}

func TestTIFFIdentificationSample(t *testing.T) {
	// 1. Initialize engine
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/tiff", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	// 2. Load the actual TIFF bytes from testdata
	tiffData, err := os.ReadFile("testdata/sample.tif")
	if err != nil {
		t.Fatalf("Failed to read test TIFF: %v", err)
	}

	// 3. Identify
	got := engine.Identify(tiffData)
	want := "TIFF image data, big-endian"

	if got == nil {
		t.Fatal("Expected identification, got nil")
	}
	if got.Message != want {
		t.Errorf("Got %q, want %q", got.Message, want)
	}
}

func TestZipIdentification(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/archive", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	zipData, err := os.ReadFile("testdata/sample.zip")
	if err != nil {
		t.Fatalf("Failed to read test ZIP: %v", err)
	}

	got := engine.Identify(zipData)
	want := "Zip archive data"

	if got == nil || got.Message != want {
		t.Errorf("Identify() = %v, want %q", got, want)
	}
}

func TestOOXMLIdentificationMock(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/archive", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	// Mock OOXML: PK\x03\x04 + some filler + [Content_Types].xml + filler + word/
	data := make([]byte, 1000)
	copy(data[0:4], "PK\x03\x04")
	copy(data[100:119], "[Content_Types].xml")
	copy(data[200:205], "word/")

	got := engine.Identify(data)
	want := "Zip archive data, Microsoft Office Open XML Microsoft Word document"

	if got == nil || got.Message != want {
		t.Errorf("Identify() = %v, want %q", got, want)
	}
}

func TestSubroutineIdentification(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/subroutines", logger)
	if err != nil {
		t.Fatalf("Failed to init: %v", err)
	}

	tests := []struct {
		data     []byte
		expected string
	}{
		{[]byte("MAGIChello"), "Magic file found, they said hello"},
		{[]byte("MAGICbye"), "Magic file found, they said goodbye"},
		{[]byte("MAGICnothing"), "Magic file found"},
	}

	for _, tt := range tests {
		got := engine.Identify(tt.data)
		if got == nil || got.Message != tt.expected {
			t.Errorf("Identify(%q) = %v, want %q", tt.data, got, tt.expected)
		}
	}
}
