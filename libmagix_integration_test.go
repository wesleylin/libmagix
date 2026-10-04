package libmagix_test

import (
	"bufio"
	"encoding/binary"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wesleylin/libmagix"
	"github.com/wesleylin/libmagix/internal/parser"
)

func TestMain(m *testing.M) {
	// file's own tests set TZ=UTC. ldate types print local time, so the
	// vendored results match when local time is UTC.
	os.Setenv("TZ", "UTC")
	time.Local = time.UTC
	os.Exit(m.Run())
}

func TestGIFIdentification(t *testing.T) {
	// 1. Setup a logger that only shows errors unless we run with -v
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// 2. Initialize the engine using the public API
	// This points to our tiny test magic file
	engine, err := libmagix.New("magic/fixtures/basicGif", logger)
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
	engine, err := libmagix.New("magic/fixtures/java", logger)
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
	engine, err := libmagix.New("magic/fixtures/elf", logger)
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
	engine, err := libmagix.New("magic/fixtures/bmp", logger)
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
	engine, err := libmagix.New("magic/fixtures/bmp", logger)
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
	engine, err := libmagix.New("magic/fixtures/script", logger)
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
	engine, err := libmagix.New("magic/fixtures/pe", logger)
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
	engine, err := libmagix.New("magic/fixtures/tiff", logger)
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
	engine, err := libmagix.New("magic/fixtures/tiff", logger)
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
	engine, err := libmagix.New("magic/fixtures/archive", logger)
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
	engine, err := libmagix.New("magic/fixtures/archive", logger)
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
	engine, err := libmagix.New("magic/fixtures/subroutines", logger)
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

func TestStarOfficeIdentification(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/fixtures/wordprocessorOfficial", logger)
	if err != nil {
		t.Fatalf("Failed to load official magic: %v", err)
	}

	// Mock StarOffice Gallery theme header (.thm)
	// Offset 0: 0x04 0x00 (ubeshort)
	// Offset 2: 0x06 00 (uleshort length prefix for pstring/h)
	// Offset 2.s+4 = 6+4 = 10: 0x01 00 00 00 (ulelong = 1 object)
	// Offset 2.s+11 = 6+11 = 17: 0x03 00 (uleshort length prefix for 1st object pstring/h)
	// Offset 2.s+13 = 6+13 = 19: 0x20 (ubyte > 0x1F to trigger main category)
	data := make([]byte, 100)
	binary.BigEndian.PutUint16(data[0:2], 0x0400)
	binary.LittleEndian.PutUint16(data[2:4], 6)
	copy(data[4:], "MyName")
	binary.LittleEndian.PutUint32(data[10:14], 1) // 1 object
	binary.LittleEndian.PutUint16(data[17:19], 3) // 1st object name length
	data[19] = 0x20                               // Trigger StarOffice Gallery theme rule at (2.s+13)
	copy(data[20:], "Obj")

	// Identify
	got := engine.Identify(data)

	// 630: "StarOffice Gallery theme"
	// 636: gallery name "MyName"
	// 638: ", 1 object"
	// 640: plural skipped because the count is 1
	// 644: first object name is 0x20, 'O', 'b'
	want := "StarOffice Gallery theme MyName, 1 object, 1st  Ob"

	if got == nil {
		t.Fatal("Expected identification, got nil")
	}
	if got.Message != want {
		t.Errorf("Got %q, want %q", got.Message, want)
	}
}

func TestDescriptionFormatting(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	identify := func(magic string, data []byte) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "formatted")
		if err := os.WriteFile(path, []byte(magic), 0644); err != nil {
			t.Fatalf("Failed to write mock magic file: %v", err)
		}
		engine, err := libmagix.New(path, logger)
		if err != nil {
			t.Fatalf("Failed to initialize engine: %v", err)
		}
		got := engine.Identify(data)
		if got == nil {
			t.Fatal("Identify() = nil")
		}
		return got.Message
	}

	count := make([]byte, 4)
	binary.LittleEndian.PutUint32(count, 42)
	if got := identify("0\tulelong\tx\tcount %u\n", count); got != "count 42" {
		t.Errorf("count = %q, want %q", got, "count 42")
	}

	// 0x0201 / 256 == 2
	if got := identify("0\tuleshort/256\tx\tversion %u\n", []byte{0x01, 0x02}); got != "version 2" {
		t.Errorf("version = %q, want %q", got, "version 2")
	}

	if got := identify("0\tstring\tx\tlabel %s\n", []byte("hello\x00")); got != "label hello" {
		t.Errorf("label = %q, want %q", got, "label hello")
	}
}

func TestUpstreamAllowlistIdentification(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatalf("load allowlisted Magdir: %v", err)
	}

	cases := []struct {
		file string
		msg  string
		mime string
	}{
		{
			file: "testdata/sample.pdf",
			msg:  "PDF document, version 1.3, 1 page(s)",
			mime: "application/pdf",
		},
		{
			file: "testdata/sample.gif",
			msg:  "GIF image data, version 89a, 400 x 300",
			mime: "image/gif",
		},
		{
			file: "testdata/sample.jpg",
			msg:  "JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16",
			mime: "image/jpeg",
		},
		{
			file: "testdata/sample.png",
			msg:  "PNG image data, 172 x 178, 8-bit/color RGB, non-interlaced",
			mime: "image/png",
		},
		{
			file: "testdata/sample.tif",
			msg:  "TIFF image data, big-endian, direntries=15, width=256, height=256, bps=8, compression=none, PhotometricInterpretation=BlackIsZero, description=MatLab PGMWRITE file, saved 27-Aug-96, orientation=upper-left",
			mime: "image/tiff",
		},
		{
			file: "testdata/blackbuck.bmp",
			msg:  "PC bitmap, Windows 3.x format, 512 x 512 x 24, image size 786432, cbSize 786486, bits offset 54",
			mime: "image/bmp",
		},
		{
			file: "testdata/sample.gz",
			msg:  "gzip compressed data, from Unix, original size modulo 2^32 3",
			mime: "application/gzip",
		},
		{
			file: "testdata/sample.elf",
			msg:  "ELF 64-bit LSB executable, no machine, invalid version (SYSV)",
			mime: "application/x-executable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatal(err)
			}
			got := engine.Identify(data)
			if got == nil {
				t.Fatal("Identify() = nil")
			}
			if got.Message != tc.msg {
				t.Errorf("message = %q, want %q", got.Message, tc.msg)
			}
			if got.Mime != tc.mime {
				t.Errorf("mime = %q, want %q", got.Mime, tc.mime)
			}
		})
	}
}

func TestDiskMagdir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	blcr := make([]byte, 24)
	copy(blcr, []byte{'C', 0, 0, 0, 'R', 0, 0, 0})
	binary.LittleEndian.PutUint32(blcr[8:], 1)
	binary.LittleEndian.PutUint32(blcr[16:], 5)
	dump := make([]byte, 32)
	binary.LittleEndian.PutUint32(dump[0:], 1)
	binary.LittleEndian.PutUint32(dump[24:], 60012)
	luks := make([]byte, 200)
	copy(luks, []byte{'L', 'U', 'K', 'S', 0xba, 0xbe})
	binary.BigEndian.PutUint16(luks[6:], 1)
	copy(luks[8:], "aes")
	copy(luks[40:], "xts-plain64")
	copy(luks[72:], "sha256")
	partclone := make([]byte, 40)
	copy(partclone, "partclone-image")
	copy(partclone[15:], "ext4")
	copy(partclone[30:], "0001")
	zfs := make([]byte, 64)
	copy(zfs[8:], []byte{0xac, 0xcb, 0xba, 0xf5, 0x02, 0, 0, 0})
	binary.LittleEndian.PutUint32(zfs[16:], 1)
	binary.LittleEndian.PutUint32(zfs[32:], 2)
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{name: "blcr", data: blcr, msg: "BLCR x86-64 context data (little endian, version 1)"},
		{name: "dump", data: dump, msg: "new-fs dump file (little endian), This dump Thu Jan  1 00:00:00 1970, Previous dump Thu Jan  1 00:00:00 1970, tape header,"},
		{name: "fusecompress", data: []byte{0x1f, 0x5d, 0x89, 0x02, 0, 0, 0, 0}, msg: "FuseCompress(ed) data (gz format) uncompressed size: 0"},
		{name: "gpt", data: append([]byte("EFI PART"), make([]byte, 64)...), msg: "GPT data structure (nonstandard: at LBA 0), version 0.0, GUID: 00000000-0000-0000-0000-000000000000, disk size: 1 sectors (sector size unknown)"},
		{name: "isz", data: append([]byte("IsZ!"), 16, 1, 0, 0, 7, 0, 0, 0), msg: "ISO Zipped file, header size 16, version 1, serial 7"},
		{name: "luks", data: luks, msg: "LUKS encrypted file, ver 1 [aes, xts-plain64, sha256] UUID: , at 0 data, 0 key bytes, MK digest 0000000000000000000000000000000000000000, MK salt 0000000000000000000000000000000000000000000000000000000000000000, 0 MK iterations"},
		{name: "partclone", data: partclone, msg: "Partclone image, version 0001, filesystem: ext4"},
		{name: "zfs", data: zfs, msg: "ZFS snapshot (little-endian machine), version 1, type: ZFS, destination GUID: 00 00 00 00 00 00 00 00,"},
		{name: "dwarfs", data: dwarfsImage(), msg: "DwarFS File System Image, version 2.5, uncompressed"},
		{name: "dwarfs-prefix", data: append([]byte("DWARFS"), make([]byte, 74)...), msg: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Identify(tc.data)
			if tc.msg == "" {
				if got != nil && strings.Contains(got.Message, "DwarFS") {
					t.Fatalf("Identify() = %q, want no DwarFS description", got.Message)
				}
				return
			}
			if got == nil {
				t.Fatalf("Identify() = nil, want %q", tc.msg)
			}
			if got.Message != tc.msg {
				t.Errorf("message = %q, want %q", got.Message, tc.msg)
			}
		})
	}
}

// dwarfsImage is two section headers. The first has a zero section number
// and type, no payload, so the next header sits at offset 0x40.
func dwarfsImage() []byte {
	img := make([]byte, 0x48)
	copy(img, "DWARFS")
	img[6], img[7] = 2, 5
	copy(img[0x40:], "DWARFS")
	img[0x46], img[0x47] = 2, 5
	return img
}

func TestExecutableMagdir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 40)
	put := func(n int, b ...byte) []byte {
		t.Helper()
		data := append([]byte(nil), zeros...)
		copy(data, b)
		if n > len(data) {
			data = append(data, make([]byte, n-len(data))...)
		}
		return data
	}
	coff := make([]byte, 24)
	coff[0], coff[1], coff[2] = 0xf0, 0x01, 1
	arm := make([]byte, 24)
	arm[0], arm[1], arm[2] = 0x64, 0xaa, 1
	mips := make([]byte, 24)
	mips[0], mips[1], mips[17] = 0x01, 0x60, 56
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{name: "aout", data: put(4, 0x07, 0x01, 0x00, 0x00), msg: "a.out little-endian 32-bit executable"},
		{name: "bflt", data: append([]byte("bFLT"), 0, 0, 0, 4), msg: "BFLT executable - version 4"},
		{name: "gcc", data: []byte("gpchC014"), msg: "GCC precompiled header (version 014) for C"},
		{name: "llvm", data: []byte{'B', 'C', 0xc0, 0xde}, msg: "LLVM IR bitcode"},
		{name: "wasm", data: []byte{0, 'a', 's', 'm', 1, 0, 0, 0}, msg: "WebAssembly (wasm) binary version 0x1 (MVP module)"},
		{name: "xo65", data: []byte{'U', 'z', 'n', 'a', 1, 0, 0, 0}, msg: "xo65 object, version 1, no debug info"},
		{name: "mach", data: []byte{0xce, 0xfa, 0xed, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0}, msg: "Mach-O executable"},
		{name: "coff", data: coff, msg: "PowerPC 32-bit (little-endian) COFF object file, not stripped, 1 section, 1st section name \"\""},
		{name: "arm", data: arm, msg: "ARM64 COFF object file, not stripped, 1 section, 1st section name \"\""},
		{name: "mips", data: mips, msg: "MIPSEB ECOFF executable stripped - version 0.0"},
		{name: "msvc", data: []byte{'H', 'W', 'B', 0, 0xff, 1, 0, 0, 0}, msg: "Microsoft Visual C .APS file"},
		{name: "intel", data: []byte{0x48, 0x01}, msg: "x86 executable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Identify(tc.data)
			if got == nil {
				t.Fatalf("Identify() = nil, want %q", tc.msg)
			}
			if got.Message != tc.msg {
				t.Errorf("message = %q, want %q", got.Message, tc.msg)
			}
		})
	}
}

func TestJavaMagdir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		data []byte
		msg  string
		mime string
	}{
		{
			name: "class",
			data: []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34},
			msg:  "compiled Java class data, version 52.0 (Java 1.8)",
			mime: "application/x-java-applet",
		},
		{
			name: "serialization",
			data: []byte{0xac, 0xed, 0x00, 0x05},
			msg:  "Java serialization data, version 5",
		},
		{
			name: "keystore",
			data: []byte{0xfe, 0xed, 0xfe, 0xed},
			msg:  "Java KeyStore",
			mime: "application/x-java-keystore",
		},
		{
			name: "source",
			data: []byte("import java.util.List;\n"),
			msg:  "Java source, ASCII text",
			mime: "text/x-java",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Identify(tc.data)
			if got == nil {
				t.Fatal("Identify() = nil")
			}
			if got.Message != tc.msg {
				t.Errorf("message = %q, want %q", got.Message, tc.msg)
			}
			if got.Mime != tc.mime {
				t.Errorf("mime = %q, want %q", got.Mime, tc.mime)
			}
		})
	}
}

func TestEasyAllowlistSignatures(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	p := parser.NewParser(logger)
	names := []string{
		"amanda", "application", "beetle", "bhl", "ebml", "karma",
		"lauterbach", "lecter", "macos", "mathcad", "metastore", "mlssa",
		"nasa", "octave", "pulsar", "svf", "teapot", "tgif", "wireless",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			rules, err := p.LoadFile(filepath.Join("magic/Magdir", name))
			if err != nil {
				t.Fatal(err)
			}
			var sig *parser.Rule
			var data []byte
			for i := range rules {
				r := &rules[i]
				if r.Level != 0 || r.MatchAny || r.Message == "" || r.Operator != "=" || r.IsIndirect {
					continue
				}
				buf, ok := signatureBytes(r)
				if !ok {
					continue
				}
				sig = r
				data = buf
				break
			}
			if sig == nil {
				t.Fatal("no level-0 signature")
			}
			got := engine.Identify(data)
			if got == nil {
				t.Fatalf("Identify() = nil, want %q", sig.Message)
			}
			if !strings.Contains(got.Message, sig.Message) {
				t.Errorf("Identify() = %q, want it to contain %q", got.Message, sig.Message)
			}
		})
	}
}

func signatureBytes(r *parser.Rule) ([]byte, bool) {
	width := 0
	var put func([]byte)
	switch r.Type {
	case "string":
		s, ok := r.Value.(string)
		if !ok || s == "" {
			return nil, false
		}
		data := make([]byte, int(r.Offset)+len(s))
		copy(data[r.Offset:], s)
		return data, true
	case "belong", "ubelong":
		v, ok := r.Value.(uint32)
		if !ok {
			return nil, false
		}
		width = 4
		put = func(b []byte) { binary.BigEndian.PutUint32(b, v) }
	case "lelong", "ulelong":
		v, ok := r.Value.(uint32)
		if !ok {
			return nil, false
		}
		width = 4
		put = func(b []byte) { binary.LittleEndian.PutUint32(b, v) }
	default:
		return nil, false
	}
	data := make([]byte, int(r.Offset)+width)
	put(data[r.Offset:])
	return data, true
}

func TestUpstreamFileSamples(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	names := readNameList(t, "tests/allowlist")
	if len(names) == 0 {
		t.Fatal("tests/allowlist is empty")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("tests", name+".testfile"))
			if err != nil {
				t.Fatal(err)
			}
			wantBytes, err := os.ReadFile(filepath.Join("tests", name+".result"))
			if err != nil {
				t.Fatal(err)
			}
			want := strings.TrimRight(string(wantBytes), "\n")
			eng := engine
			if paths, err := filepath.Glob(filepath.Join("tests", name+"*.magic")); err == nil && len(paths) > 0 {
				eng, err = libmagix.NewFiles(paths, logger)
				if err != nil {
					t.Fatal(err)
				}
			}
			var got *libmagix.Result
			if continueFlags(filepath.Join("tests", name+".flags")) {
				got = eng.IdentifyContinue(data)
			} else {
				got = eng.Identify(data)
			}
			if got == nil {
				t.Fatalf("Identify() = nil, want %q", want)
			}
			if got.Message != want {
				t.Errorf("message = %q, want %q", got.Message, want)
			}
		})
	}
}

func continueFlags(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, f := range strings.Fields(string(b)) {
		if f == "k" || f == "-k" {
			return true
		}
	}
	return false
}

func readNameList(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var names []string
	for sc := bufio.NewScanner(f); sc.Scan(); {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		names = append(names, line)
	}
	return names
}
