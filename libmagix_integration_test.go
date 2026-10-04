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

func TestMediaMagdir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	xcf := make([]byte, 26)
	copy(xcf, "gimp xcf file")
	binary.BigEndian.PutUint32(xcf[14:], 0x0a00)
	binary.BigEndian.PutUint32(xcf[18:], 0x1400)
	icc := make([]byte, 44)
	icc[4] = 1
	icc[26], icc[27] = 0, 1
	copy(icc[36:], "acspAPPL")
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{name: "asf", data: []byte{0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c}, msg: "Microsoft ASF"},
		{name: "bm", data: append([]byte("bm\x01\xa4"), make([]byte, 20)...), msg: "Birtual Machine, version 0, program size 0, memory size 0"},
		{name: "blender", data: append([]byte("BLENDER-v279"), make([]byte, 8)...), msg: "Blender3D pre-v5, saved as 64-bits little endian with version 2.79"},
		{name: "cddb", data: []byte("# xmcd\n"), msg: "CDDB(tm) format CD text data, ASCII text"},
		{name: "chord", data: []byte("{title foo}\n"), msg: "Chord text file"},
		{name: "cubemap", data: []byte("CUBE"), msg: "Map file for cube and cube2 engine games"},
		{name: "dolby", data: []byte{0x0b, 0x77, 0, 0, 0, 0}, msg: "ATSC A/52 aka AC-3 aka Dolby Digital stream, 48 kHz,, complete main (CM), 32 kbit/s"},
		{name: "flash-flv", data: []byte("FLV\x01\x05\x00\x00\x00\x09"), msg: "Macromedia Flash Video"},
		{name: "flash-swf", data: []byte{'F', 'W', 'S', 10, 20, 0, 0, 0, 0x08}, msg: "Macromedia Flash data, version 10"},
		{name: "flif", data: append([]byte("FLIF31"), 0, 10, 0, 20), msg: "FLIF image data, 10x20, 8-bit/color,, RGB, non-interlaced"},
		{name: "fonts-woff", data: append([]byte("wOFF"), make([]byte, 24)...), msg: "Web Open Font Format, flavor 0, length 0, version 0.0"},
		{name: "fonts-otf", data: append([]byte("OTTO"), make([]byte, 16)...), msg: "OpenType font data"},
		{name: "fonts-figlet", data: []byte("flf2a"), msg: "FIGlet font"},
		{name: "gimp", data: xcf, msg: "GIMP XCF image data, version 0, 2560 x 5120, RGB Color"},
		{name: "icc", data: icc, msg: "ColorSync color profile 0.0, - device, 0 bytes, 0-1-0"},
		{name: "iff", data: []byte("FORM\x00\x00\x00\x00AIFF"), msg: "IFF data, AIFF audio"},
		{name: "matroska", data: []byte{0x1a, 0x45, 0xdf, 0xa3, 0x42, 0x82, 0x88, 'm', 'a', 't', 'r', 'o', 's', 'k', 'a'}, msg: "Matroska data"},
		{name: "webm", data: []byte{0x1a, 0x45, 0xdf, 0xa3, 0x42, 0x82, 0x84, 'w', 'e', 'b', 'm'}, msg: "WebM"},
		{name: "ebml", data: []byte{0x1a, 0x45, 0xdf, 0xa3, 0, 0, 0, 0}, msg: "EBML file"},
		{name: "mup", data: []byte("//!Mup\n"), msg: "Mup music publication program input, ASCII text"},
		{name: "music-bagpipe", data: []byte("Bagpipe Reader 1.0"), msg: "Bagpipe Reader (version 1.0)"},
		{name: "music-brpp", data: []byte("BRPP"), msg: "Bars & Pipes Professional"},
		{name: "pbm", data: []byte{0x2a, 0x17}, msg: `"compact bitmap" format (Poskanzer)`},
		{name: "riff", data: append([]byte("RIFF"), 0, 0, 0, 0, 'W', 'A', 'V', 'E'), msg: "RIFF (little-endian) data, WAVE audio"},
		{name: "sketch", data: []byte("##Sketch 1 2"), msg: "Sketch document, ASCII text, with no line terminators"},
		{name: "subtitle", data: []byte("WEBVTT\n\n00:00:00.000 --> 00:00:01.000\nHi\n"), msg: "WebVTT subtitles, ASCII text"},
		{name: "sysex", data: []byte{0xF0, 0x00, 0x01, 0xF7}, msg: "MIDI audio System Exclusive (SysEx) message - ID EXTENSIONS"},
		{name: "vorbis", data: append(append([]byte("OggS"), make([]byte, 24)...), []byte("\x01vorbis")...), msg: "Ogg data, Vorbis audio,"},
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

func TestSecurityMagdir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	btc := make([]byte, 96)
	copy(btc, []byte{0xf9, 0xbe, 0xb4, 0xd9})
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{name: "aes", data: []byte("AES\x00\x00"), msg: "AES encrypted data, version 0"},
		{name: "cracklib", data: []byte{0x31, 0x56, 0x77, 0x70, 0, 0, 0, 1}, msg: "Cracklib password index, little endian (1 words)"},
		{name: "bitcoin", data: btc, msg: "Bitcoin block, size 0, version 0x0, Thu Jan  1 00:00:00 1970 UTC, txcount 0"},
		{name: "scrypt", data: append([]byte("scrypt\x00"), make([]byte, 12)...), msg: "scrypt encrypted file, N=2**0, r=0, p=0"},
		{name: "age", data: []byte("age-encryption.org/v1\n"), msg: "age encrypted file"},
		{name: "fsav", data: []byte{0x15, 0x75}, msg: "fsav macro virus signatures"},
		{name: "clamav", data: []byte("ClamAV-VDB:"), msg: "Clam AntiVirus file"},
		{name: "avg", data: []byte("AVG7_ANTIVIRUS_VAULT_FILE"), msg: "AVG 7 Antivirus vault file data"},
		{name: "gringotts", data: []byte("GRG1"), msg: "Gringotts data file v.1, MCRYPT S2K, SERPENT crypt, SHA-256 hash, ZLib lvl.9"},
		{name: "keepass", data: []byte{0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5}, msg: "Keepass password database 2.x KDBX"},
		{name: "kerberos", data: []byte{0x05, 0x02, 0x00, 0x00}, msg: "Kerberos Keytab file"},
		{name: "mcrypt", data: []byte{0x00, 'm', 0x02, 0x00}, msg: "mcrypt 2.2 encrypted data, algorithm: blowfish-448,"},
		{name: "opentimestamps", data: []byte("\x00OpenTimestamps\x00"), msg: "OpenTimestamps"},
		{name: "pgp", data: []byte("-----BEGIN PGP MESSAGE-\n"), msg: "PGP message"},
		{name: "pwsafe", data: []byte("PWS3"), msg: "Password Safe V3 database"},
		{name: "securitycerts", data: []byte("-----BEGIN NEW CERTIFICATE\n"), msg: "RFC1421 Security Certificate Signing Request, ASCII text"},
		{name: "jks", data: []byte{0xed, 0xfe, 0xed, 0xfe}, msg: "Sun 'jks' Java Keystore File data"},
		{name: "selinux", data: []byte{0x8f, 0xff, 0x7c, 0xf9, 1, 0, 0, 0}, msg: "SE Linux modular policy version 1,"},
		{name: "selinux-source", data: []byte("\npolicy_module(foo)\n"), msg: "SE Linux policy module source"},
		{name: "ssh", data: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), msg: "OpenSSH private key"},
		{name: "ssh-ed25519", data: []byte("ssh-ed25519 AAAA"), msg: "OpenSSH ED25519 public key"},
		{name: "ssl", data: []byte("-----BEGIN CERTIFICATE-----\n"), msg: "PEM certificate"},
		{name: "openssl", data: []byte("Salted__"), msg: "openssl enc'd data with salted password"},
		{name: "yara", data: []byte{'Y', 'A', 'R', 'A', 0, 8, 0, 0, 11}, msg: "YARA 3.x compiled rule set created with version 3.5.0"},
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

func TestDataMagdir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	sqlite := make([]byte, 80)
	copy(sqlite, "SQLite format 3\x00")
	sqlite[16], sqlite[17] = 0, 1
	gguf := make([]byte, 24)
	copy(gguf, "GGUF")
	gguf[4] = 3
	ber := make([]byte, 90)
	ber[0] = 0x61
	ber[2] = 0x64
	copy(ber[4:], []byte{0x5f, 0x81, 0x44})
	copy(ber[71:], []byte{0x5f, 0x81, 0x49, 0x01, 0x03, 0x5f, 0x81, 0x3d, 0x01, 12})
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{name: "a2ml", data: []byte("@abstract: hello\n"), msg: "A2ML Attested Markup Language document"},
		{name: "ber", data: ber, msg: "TAP 3.12 Batch (TD.57, Transferred Account)"},
		{name: "cbor", data: []byte{0xd9, 0xd9, 0xf7, 0x00}, msg: "Concise Binary Object Representation (CBOR) container (positive integer)"},
		{name: "gdbm", data: []byte{0x13, 0x57, 0x9a, 0xcd}, msg: "GNU dbm 1.x or ndbm database, big endian, 32-bit"},
		{name: "gdbm2", data: []byte("GDBM"), msg: "GNU dbm 2.x database"},
		{name: "dif", data: append(append([]byte("TABLE\n0,\n"), make([]byte, 40)...), []byte("TUPLES")...), msg: "Data Interchange Format"},
		{name: "gguf", data: gguf, msg: "GGUF file format version 3, 0 tensors"},
		{name: "marc21", data: append([]byte("00024na  a2200000   4500"), 0x1e), msg: "MARC21 Bibliographic"},
		{name: "numpy", data: []byte{0x93, 'N', 'U', 'M', 'P', 'Y', 1, 0, 0, 0}, msg: "NumPy array, version 1.0, header length 0"},
		{name: "pbf", data: []byte("\x00\x00\x00\x00\x0a\x09OSMHeader"), msg: "OpenStreetMap Protocolbuffer Binary Format"},
		{name: "psdbms", data: append([]byte{0x56, 0x31, 0x00, 0x00}, "kern"...), msg: "ps database version 1 from kernel kern"},
		{name: "sereal", data: []byte("=srl\x00\x00\x00\x00\x00"), msg: "Sereal data packet (version 0, uncompressed)"},
		{name: "smile", data: []byte(":)\n\x00"), msg: "Smile binary data version 0: binary encoded, shared String values disabled, shared field names disabled"},
		{name: "sqlite", data: sqlite, msg: "SQLite 3.x database, page size 65536, writer version 0, read version 0, maximum payload 0, minimum payload 0, leaf payload 0, file counter 0, database pages 0, cookie 0, schema 0, unknown 0 encoding"},
		{name: "sqlite2", data: []byte("** This file contains an SQLite\n"), msg: "SQLite 2.x database"},
		{name: "mysql", data: []byte{0xfe, 0x01, 10, 9}, msg: "MySQL table definition file Version 10, type MYISAM"},
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

func TestArchiveMagdir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	arc := make([]byte, 516)
	binary.LittleEndian.PutUint32(arc[0:], 0xdddddddd)
	binary.LittleEndian.PutUint32(arc[512:], 0xabbaabba)
	nova := make([]byte, 56)
	nova = append(nova, []byte("<<NoVaStOr>>")...)
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{name: "apt", data: []byte{0x98, 0xfe, 0x76, 0xdc, 0, 0, 0, 0, 0, 0, 0, 0}, msg: "APT cache data, version 0.0, 32 bit big-endian"},
		{name: "burp", data: []byte{0x66, 0x85, 0x82, 0x80, 0, 0, 0, 1}, msg: "Burp project save file"},
		{name: "dact", data: []byte{0x44, 0x43, 0x54, 0xc3, 1, 2, 3}, msg: "DACT compressed data"},
		{name: "nix", data: []byte("{\nstdenv.mkDerivation {\n"), msg: "Nix package definition"},
		{name: "pkgadd", data: []byte("# PaCkAgE DaTaStReAm\n"), msg: "pkg Datastream (SVR4)"},
		{name: "qic", data: append([]byte("VTBL"), append(make([]byte, 4), []byte("backup")...)...), msg: "QIC-80 tape volume header, Volume label: backup"},
		{name: "colorado", data: []byte{0x55, 0xaa, 0x55, 0xaa, 2, 0, 0, 0}, msg: "Colorado tape backup"},
		{name: "novastor", data: nova, msg: "NovaStor tape backup"},
		{name: "arcserve", data: arc, msg: "ArcServe tape backup"},
		{name: "savlib", data: []byte{0xff, 0xff, 0xff, 0xff, 0xd8, 0xe2, 0xd9, 0xc4}, msg: "AS/400 SAVLIB backup"},
		{name: "txplus", data: []byte{0x3a, 0x3a, 0x3a, 0x3a, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x3a, 0x3a, 0x3a}, msg: "TXPLUS tape backup"},
		{name: "mountain", data: []byte{0x04, 0x00, 0xaa, 0x55}, msg: "Mountain FileSafe tape backup"},
		{name: "warc", data: []byte("WARC/1.0\n"), msg: "WARC Archive version 1.0"},
		{name: "ia-arc", data: []byte("filedesc://\n2"), msg: "Internet Archive File version 2"},
		{name: "xdelta", data: []byte("%XDZ004%"), msg: "XDelta binary patch file 1.1"},
		{name: "vcdiff", data: []byte{0xd6, 0xc3, 0xc4, 0x00}, msg: "VCDIFF binary diff"},
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

func TestDesktopGamesScience(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	kml := append([]byte("<?xml version=\"1.0\"?>\n"), []byte(" xmlns='http://earth.google.com/kml2.2'")...)
	vxl := []byte{1, 0, 0x4e, 0x2c, 0x2b, 0x47}
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{name: "gnome", data: []byte("GnomeKeyring\n\r\x00\n"), msg: "GNOME keyring"},
		{name: "kde", data: []byte("[KDE Desktop Entry]\n"), msg: "KDE desktop entry, ASCII text"},
		{name: "qt", data: []byte("<!DOCTYPE RCC>\n"), msg: "Qt Resource Collection file"},
		{name: "xwindows", data: []byte("xkm\x01"), msg: "Compiled XKB Keymap: msb, version 1"},
		{name: "adventure", data: []byte("Glul"), msg: "Glulx game data"},
		{name: "allegro", data: []byte{0x73, 0x6c, 0x68, 0x21}, msg: "Allegro datafile (packed)"},
		{name: "creativeassembly", data: []byte{0x50, 0x46, 0x48, 0x34}, msg: "Creative Assembly Archive version 4"},
		{name: "dbpf", data: []byte("DBPF"), msg: "Maxis Database Packed File"},
		{name: "games", data: []byte("IWAD"), msg: "doom main IWAD data"},
		{name: "playdate", data: []byte("Playdate IMG"), msg: "Playdate image data"},
		{name: "puzzle", data: append([]byte{0, 0}, []byte("ACROSS&DOWN")...), msg: "PUZ crossword puzzle"},
		{name: "asterix", data: []byte("*STA"), msg: "Aster*x"},
		{name: "bioinformatics", data: []byte("BAM\x01"), msg: "SAMtools BAM (Binary Sequence Alignment/Map)"},
		{name: "biosig", data: []byte("GDF"), msg: "Biosig/GDF: General data format for biosignals"},
		{name: "cad", data: []byte("AC1032"), msg: "DWG AutoDesk AutoCAD 2018/2019/2020"},
		{name: "dataone", data: []byte("<DryadDatadryad-bibo/v3.1\n"), msg: "https://datadryad.org/profile/v3.1"},
		{name: "esri", data: []byte{0, 0, 0x27, 0x0a}, msg: "ESRI Shapefile"},
		{name: "fcs", data: []byte("FCS3.0"), msg: "Flow Cytometry Standard (FCS) data, version 3.0"},
		{name: "geo", data: []byte("LASF"), msg: "LIDAR point data records"},
		{name: "grace", data: []byte("# Grace project file\n"), msg: "Grace project file"},
		{name: "kicad", data: []byte("(kicad_pcb "), msg: "KiCad Board Layout"},
		{name: "kml", data: kml, msg: "Google KML document, ASCII text"},
		{name: "lammps", data: []byte("LAMMPS data file\n"), msg: "LAMMPS data file"},
		{name: "measure", data: []byte("MDF     4.10"), msg: "ASAM/MDF measurement file Version"},
		{name: "meteorological", data: []byte("GRIB\x00\x00\x00\x01"), msg: "Gridded binary (GRIB) version 1"},
		{name: "olf", data: []byte{0x7f, 'O', 'L', 'F', 1}, msg: "OLF 32-bit"},
		{name: "openfst", data: []byte{0x7e, 0xb2, 0xfd, 0xd6}, msg: "OpenFst binary FST data"},
		{name: "psl", data: []byte(".DAFSA@PSL_1xxx\n"), msg: "Public Suffix List data (optimized) (Version 1)"},
		{name: "sosi", data: []byte("..OMR\n..TRANSPAR\n.HODE\n"), msg: "SOSI map data, ASCII text"},
		{name: "statistics", data: []byte("<stata_dta><header><release>"), msg: "Stata Data File"},
		{name: "usd", data: []byte("#usda 1.0\n"), msg: "USD ASCII, version 1.0"},
		{name: "uterus", data: []byte("UTE+"), msg: "uterus file"},
		{name: "vicar", data: []byte("LBLSIZE="), msg: "PDS (VICAR) image data"},
		{name: "visx", data: []byte{0x55, 0x55}, msg: "VISX image file"},
		{name: "vxl", data: vxl, msg: "VXL data file, schema version no 1"},
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

func TestPlatformMagdir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	os400 := make([]byte, 1090)
	os400 = append(os400, 0x19, 0xdb, 0xd8, 0xe2, 0xd9, 0xc4, 0xe2, 0xe2, 0xd7, 0xc3, 0x00)
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{name: "acorn", data: []byte{0xc5, 0xc6, 0xcb, 0xc3}, msg: "RISC OS Chunk data"},
		{name: "alliant", data: []byte{0x1, 0x10}, msg: "0420 Alliant virtual executable"},
		{name: "amigaos", data: []byte{0x0, 0x0, 0x3, 0xfa}, msg: "AmigaOS shared library"},
		{name: "atari", data: append([]byte{0x60, 0x1e}, make([]byte, 30)...), msg: "0000-00-00 Video: NTSC Locale: en-US"},
		{name: "att3b", data: []byte{0x1, 0x70}, msg: "WE32000 COFF"},
		{name: "basis", data: []byte{0x3c, 0x3c, 0x62, 0x62, 0x78, 0x3e, 0x3e, 0x0}, msg: "BBx indexed file"},
		{name: "blackberry", data: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x10, 0x8}, msg: "BlackBerry RIM ETP file"},
		{name: "blit", data: []byte{0x7, 0x1}, msg: "VAX-order 68K Blit (standalone) executable"},
		{name: "bsdi", data: []byte{0xcc, 0x0, 0x0, 0x0}, msg: "i386 compact demand paged pure executable"},
		{name: "c64", data: []byte{0x43, 0x15, 0x41, 0x64}, msg: "X64 Image"},
		{name: "convex", data: []byte{0x0, 0x1, 0x12, 0x57}, msg: "Core file"},
		{name: "digital", data: []byte{0x21, 0x3c, 0x61, 0x72, 0x63, 0x68, 0x3e, 0xa, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x36, 0x34, 0x45, 0x0}, msg: "Alpha archive"},
		{name: "dyadic", data: []byte{0x60, 0x60}, msg: "Dyalog APL transfer"},
		{name: "encore", data: []byte{0x1, 0x54}, msg: "Encore"},
		{name: "epoc", data: []byte{0x37, 0x0, 0x0, 0x10}, msg: "Psion Series 5"},
		{name: "freebsd", data: []byte{0x7, 0x1, 0x86, 0x0}, msg: "FreeBSD/i386"},
		{name: "geos", data: []byte{0xc7, 0x45, 0xc1, 0x53}, msg: "GEOS"},
		{name: "hitachi-sh", data: []byte{0xa2, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, msg: "Hitachi SH3 COFF object file, not stripped, 1 section"},
		{name: "hp", data: []byte{0x1, 0x97}, msg: "Apollo m68k COFF executable"},
		{name: "ibm370", data: []byte{0x1, 0x5f}, msg: "370 XA sysV executable"},
		{name: "ibm6000", data: []byte{0x1, 0x4}, msg: "shared library"},
		{name: "linux", data: []byte{0x7, 0x1, 0x64, 0x0}, msg: "Linux/i386 impure executable (OMAGIC)"},
		{name: "macintosh", data: []byte{0x53, 0x49, 0x54, 0x21, 0x0}, msg: "StuffIt Archive (data) : T!"},
		{name: "microfocus", data: []byte{0x30, 0x0, 0x0, 0x7c, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3e}, msg: "Micro Focus File with Header (DAT)"},
		{name: "mirage", data: []byte{0x0, 0x0, 0x7a, 0xb7}, msg: "Mirage Assembler m.out executable"},
		{name: "motorola", data: []byte{0x1, 0x50}, msg: "mc68k COFF"},
		{name: "msx", data: []byte{0x4d, 0x47, 0x53, 0x0}, msg: "MSX Gigamix MGSDRV3 music file,"},
		{name: "ncr", data: []byte{0x1, 0x88}, msg: "Tower/XP rel 2 object"},
		{name: "netbsd", data: []byte{0x0, 0x86, 0x1, 0xb}, msg: "a.out NetBSD/i386 demand paged executable"},
		{name: "netware", data: []byte{0x4e, 0x65, 0x74, 0x57, 0x61, 0x72, 0x65, 0x20, 0x4c, 0x6f, 0x61, 0x64, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x0}, msg: "NetWare Loadable Module"},
		{name: "oric", data: []byte{0x16, 0x16, 0x16, 0x24, 0x0}, msg: "Oric tape,"},
		{name: "os2", data: []byte{0x48, 0x53, 0x50, 0x1, 0x9b, 0x0, 0x0}, msg: "OS/2 INF"},
		{name: "os400", data: os400, msg: "IBM OS/400 save file data"},
		{name: "os9", data: []byte{0x87, 0xcd}, msg: "OS9/6809 module:"},
		{name: "osf1", data: []byte{0x0, 0x0, 0xef, 0xbe}, msg: "OSF/Rose object"},
		{name: "palm", data: append(make([]byte, 60), []byte("SDocSilX\x00")...), msg: "iSiloX E-book"},
		{name: "parix", data: []byte{0x8a, 0xce}, msg: "PARIX T800"},
		{name: "pc98", data: []byte{0x4d, 0x41, 0x4b, 0x49, 0x30, 0x31, 0x0}, msg: "Maki-chan v1.%c image"},
		{name: "pdp", data: []byte{0x6d, 0x83, 0x0, 0x0}, msg: "PDP-11 single precision APL workspace"},
		{name: "plan9", data: []byte{0x3a, 0x11, 0x1, 0x3c}, msg: "Plan 9 object file, MIPS R3000"},
		{name: "plus5", data: []byte{0x2, 0x59}, msg: "mumps avl global"},
		{name: "pyramid", data: []byte{0x50, 0x90, 0x1, 0x7}, msg: "Pyramid 90x family executable"},
		{name: "sequent", data: []byte{0xea, 0x0, 0x0, 0x0}, msg: "BALANCE NS32000 .o"},
		{name: "sgi", data: []byte{0x6b, 0x62, 0x64, 0x21, 0x6d, 0x61, 0x70, 0x0}, msg: "kbd map file"},
		{name: "sinclair", data: []byte{0x51, 0x4c, 0x35, 0x0}, msg: "QL disk dump data,"},
		{name: "spectrum", data: []byte{0x50, 0x4c, 0x55, 0x53, 0x33, 0x44, 0x4f, 0x53, 0x1a, 0x0}, msg: "Spectrum +3 data"},
		{name: "sun", data: []byte{0x0, 0x8, 0x4, 0x56}, msg: "SunOS core file"},
		{name: "symbos", data: []byte{0x49, 0x4e, 0x46, 0x4f, 0x71, 0x0}, msg: "SymbOS DOX document"},
		{name: "uxn", data: []byte{0xa0, 0x0, 0x0, 0x80, 0x6, 0x37}, msg: "Varvara Uxn ROM with metadata at 0x0"},
		{name: "vax", data: []byte{0x6f, 0x83, 0x0, 0x0}, msg: "VAX single precision APL workspace"},
		{name: "vms", data: []byte{0xb0, 0x0, 0x30, 0x0, 0x0}, msg: "VMS VAX executable"},
		{name: "x68000", data: []byte{0x50, 0x49, 0x43, 0x1a, 0x0, 0x0}, msg: "Yanagisawa PIC image file,"},
		{name: "xenix", data: []byte{0x63, 0x6f, 0x72, 0x65, 0x0}, msg: "core file (Xenix)"},
		{name: "zilog", data: []byte{0x0, 0x0, 0xe8, 0x7}, msg: "object file (z8000 a.out)"},
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

func TestTextMailMagdir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	for _, prose := range []string{
		"Hello, world.\n",
		"The quick brown fox jumps over the lazy dog.\n",
		"package main\n\nimport \"fmt\"\n",
	} {
		got := engine.Identify([]byte(prose))
		if got == nil || !strings.HasPrefix(got.Message, "ASCII text") {
			t.Errorf("prose %q identified as %v", prose, got)
		}
	}
	gnumeric := append(make([]byte, 39), []byte("<gmr:Workbook")...)
	sc := append(make([]byte, 38), []byte("Spreadsheet")...)
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{name: "applix", data: []byte("*BEGIN\n"), msg: "Applixware"},
		{name: "claris", data: []byte{0x10, 0xe1, 0x00, 0x00, 0x08, 0x08}, msg: "Claris Works palette files .plt"},
		{name: "commands", data: []byte("#!/bin/sh\n"), msg: "POSIX shell script, ASCII text executable"},
		{name: "console", data: []byte("NES\x1a"), msg: "NES ROM image (iNES)"},
		{name: "diff", data: []byte("diff -u a b\n"), msg: "diff output, ASCII text"},
		{name: "editors", data: []byte("@CT \n"), msg: "T602 document data,"},
		{name: "frame", data: []byte("<MIFFile\n"), msg: "FrameMaker MIF (ASCII) file"},
		{name: "gnumeric", data: gnumeric, msg: "Gnumeric spreadsheet"},
		{name: "interleaf", data: []byte{0x88, 'O', 'P', 'S', '\n'}, msg: "Interleaf saved data"},
		{name: "ispell", data: []byte{0x00, 0x96}, msg: "little endian ispell hash file (?),"},
		{name: "locoscript", data: []byte("JOY\x01\x01"), msg: "LocoScript 1 document"},
		{name: "mail.news", data: []byte("Received:\n"), msg: "RFC 822 mail text"},
		{name: "make", data: []byte("all:\n"), msg: "makefile script, ASCII text"},
		{name: "mime", data: []byte("Content-Type: text/plain\n"), msg: "text/plain, ASCII text"},
		{name: "mmdf", data: []byte("\x01\x01\x01\x01\nFrom \n"), msg: "MMDF mailbox"},
		{name: "news", data: []byte("StartFontMetrics\n"), msg: "ASCII font metrics"},
		{name: "oasis", data: []byte("%SEMI-OASIS\r\n\n"), msg: "OASIS Stream file"},
		{name: "pgf", data: []byte("PGF\n"), msg: "Progressive Graphics image data,"},
		{name: "rst", data: []byte("====\n====\n:Author: me\n"), msg: "ReStructuredText file, ASCII text"},
		{name: "sc", data: sc, msg: "sc spreadsheet file"},
		{name: "sendmail", data: []byte("divert(-1)\n\n"), msg: "sendmail m4 text file"},
		{name: "sisu", data: []byte("SiSU text\n"), msg: "SiSU, ASCII text"},
		{name: "softquad", data: []byte("<!SQ DTD>\n"), msg: "Compiled SGML rules file Type"},
		{name: "sylk", data: []byte("ID;PGnumeric\n"), msg: "spreadsheet interchange document, created by Gnumeric"},
		{name: "tex", data: []byte{0xf7, 0x83}, msg: "TeX generic font data"},
		{name: "troff", data: []byte{0x40, 0xef}, msg: "very old (C/A/T) troff output data"},
		{name: "typeset", data: []byte("Interpress/Xerox\n"), msg: "Xerox InterPress data"},
		{name: "unicode", data: []byte("+/v8\n"), msg: "Unicode text, UTF-7"},
		{name: "uuencode", data: []byte("xbtoa Begin\n"), msg: "btoa'd, ASCII text"},
		{name: "varied.out", data: []byte("Joy!peffpwpc"), msg: "header for PowerPC PEF executable"},
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

func TestSystemProductMagdir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	aria := append([]byte{0x00, 0x01}, make([]byte, 12)...)
	aria = append(aria, 0, 0, 0, 0, 0, 0, 0, 1)
	ccf := make([]byte, 32)
	copy(ccf[8:], "@\xa5Z@_CCF")
	ccf = append(ccf, []byte("CCF\x00")...)
	lif := []byte{
		0x80, 0x00, 'A', 'A', 'A', 'A', 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	vacuum := make([]byte, 44)
	putLE := func(off int, v uint32) { binary.LittleEndian.PutUint32(vacuum[off:], v) }
	putLE(0, 1)
	putLE(4, 100)
	putLE(8, 10000)
	putLE(12, 50)
	putLE(16, 50000)
	putLE(20, 100)
	putLE(24, 1000)
	putLE(28, 1000)
	putLE(32, 5)
	putLE(36, 10)
	putLE(40, 100)
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{name: "gconv", data: []byte{0x24, 0x03, 0x01, 0x20}, msg: "gconv module configuration cache data"},
		{name: "glibc", data: []byte{0x20, 0x07, 0x09, 0x20}, msg: "glibc locale file LC_CTYPE"},
		{name: "gnu", data: []byte{0xde, 0x12, 0x04, 0x95}, msg: "GNU message catalog (little endian),"},
		{name: "magic", data: []byte("# Magic \n"), msg: "magic text file for file(1) cmd, ASCII text"},
		{name: "sysstat", data: []byte{0x96, 0xd5, 0x75, 0x21}, msg: "sysstat sar data (format 0x2175)"},
		{name: "terminfo", data: []byte{0x01, 0x1b}, msg: "SVr2 curses screen image, big-endian"},
		{name: "timezone", data: []byte("TZif\n"), msg: "timezone data(fat), version"},
		{name: "tuxedo", data: append([]byte{0, 0, 1, 0x9e}, make([]byte, 12)...), msg: "BEA TUXEDO DES mask data"},
		{name: "virtual", data: []byte("conectix\n"), msg: "Microsoft Disk Image, Virtual Server or Virtual PC"},
		{name: "virtutech", data: []byte{0x89, 0xbf, 0x1e, 0x83}, msg: "Virtutech CRAFF"},
		{name: "vmware", data: []byte("MRVN"), msg: "VMware nvram"},
		{name: "unknown", data: []byte{0x00, 0x00, 0x01, 0x0c}, msg: "unknown demand paged pure executable"},
		{name: "andrew", data: []byte("\\begindata{raster,\n"), msg: "Andrew Toolkit raster image data"},
		{name: "aria", data: aria, msg: "aria2 control file, version 1, piece length 0x0, total length 1"},
		{name: "bsi", data: []byte("XIA1\r\n"), msg: "Chiasmus Encrypted data"},
		{name: "ccf", data: ccf, msg: "Philips Pronto IR remote control CCF"},
		{name: "citrus", data: []byte("RuneCT\n"), msg: "Citrus locale declaration for LC_CTYPE"},
		{name: "diamond", data: []byte("<list>\n<protocol bbn-m\n"), msg: "Diamond Multimedia Document"},
		{name: "island", data: append([]byte{0, 0, 0, 0}, []byte("pgscriptver")...), msg: "IslandWrite document"},
		{name: "k9", data: []byte("K9!\n"), msg: "K9 Self-Validating Component"},
		{name: "lif", data: lif, msg: "lif file \"AAAA\", version 0, LIF identifier 0, directory start address 0 length 0"},
		{name: "misctools", data: []byte("%%!!\n"), msg: "X-Post-It-Note, ASCII text"},
		{name: "nifty", data: []byte("\x00\x00\x00\x00n+2\x00\r\n\x1a\n"), msg: "NIfTI-2 neuroimaging data, invalid sizeof_hdr=0"},
		{name: "nitpicker", data: []byte("NPFF\n"), msg: "NItpicker Flow File V10."},
		{name: "ringdove", data: []byte("Netlist(Freeze)\n"), msg: "pcb-rnd or gEDA/PCB netlist forward annotation action script, ASCII text"},
		{name: "sf3", data: []byte{0x81, 'S', 'F', '3', 0x00, 0xe0, 0xd0, 0x0d, 0x0a, 0x0a}, msg: "SF3"},
		{name: "syd", data: []byte("\x7fSYD\n"), msg: "SYD encrypted file, version 10"},
		{name: "unisig", data: []byte{0xdc, 0xdc, 0x0d, 0x0a, 0x1a, 0x0a, 0x00}, msg: "Unisig:"},
		{name: "vacuum-cleaner", data: vacuum, msg: "LG robot VR6[234]xx 5m^2 navigation"},
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

func TestNetworkMagdir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{name: "avro", data: []byte("Obj\x01"), msg: "Apache Avro, version 1"},
		{name: "parquet", data: []byte("PAR1"), msg: "Apache Parquet file"},
		{name: "sequence", data: []byte("SEQ\x01"), msg: "Apache Hadoop Sequence file version 1"},
		{name: "btsnoop", data: append([]byte("btsnoop\x00"), 0, 0, 0, 1, 0, 0, 0x03, 0xe9), msg: "BTSnoop version 1, Unencapsulated HCI"},
		{name: "cisco", data: []byte{0x85, 0x01, 0x14, 0x00}, msg: "cisco IOS microcode"},
		{name: "ttcn", data: []byte("$Suite\n"), msg: "TTCN Abstract Test Suite"},
		{name: "finger", data: []byte("FP1"), msg: "libfprint fingerprint data V1"},
		{name: "modem", data: []byte("PVF1\n"), msg: "portable voice format"},
		{name: "mozilla", data: []byte("mozLz40\x00"), msg: "Mozilla lz4 compressed data"},
		{name: "netscape", data: []byte("# Netscape folder cache\n"), msg: "Netscape folder cache"},
		{name: "nfdump", data: []byte{0x0c, 0xa5, 1, 0}, msg: "nfdump binary flow data (little-endian)"},
		{name: "pcap", data: append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, make([]byte, 20)...), msg: "pcap capture file, microsecond ts (little-endian) - version 0.0 (No link-layer encapsulation, capture length 0)"},
		{name: "adblock", data: []byte("[Adblock Plus]\n"), msg: "Adblock Plus rules file"},
		{name: "wsdl", data: append([]byte("wsdl"), 1, 0, 0, 0, 0, 0, 0, 0), msg: "PHP WSDL cache, version 0x1, created Thu Jan  1 00:00:00 1970"},
		{name: "zyxel", data: []byte("ZyXEL\x02"), msg: "ZyXEL voice data"},
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

func TestDevtoolMagdir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{name: "coverage", data: []byte{0x6f, 0x6e, 0x63, 0x67, 0, 0x41, 0, 0x42}, msg: "GCC gcno coverage (-ftest-coverage), version B.A"},
		{name: "ctags", data: []byte("!_TAG_FILE_FORMAT\t2\n"), msg: "Exuberant Ctags tag file, ASCII text"},
		{name: "ctf", data: []byte{0xc1, 0x1f, 0xfc, 0xc1}, msg: "Common Trace Format (CTF) trace data (LE)"},
		{name: "git", data: []byte("blob 1\n"), msg: "Git blob 1"},
		{name: "mercurial", data: []byte("HG10"), msg: "Mercurial changeset bundle"},
		{name: "mkid", data: []byte{0xc9, 0xc4}, msg: "ID tags data"},
		{name: "modulefile", data: []byte("#%Module\n"), msg: "modulefile"},
		{name: "project", data: []byte("FTNCHEK_ PROJECT\n"), msg: "project file for ftnchek"},
		{name: "revision", data: []byte{'D', 'I', 'R', 'C', 0, 0, 0, 2, 0, 0, 0, 1}, msg: "Git index, version 2, 1 entries"},
		{name: "sccs", data: []byte("\x01h01207\n\x01s "), msg: "SCCS v4 archive data"},
		{name: "spec", data: []byte("BEGIN SPECWEB"), msg: "SPECweb"},
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

func TestMoreLanguages(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	ofw := make([]byte, 36)
	binary.BigEndian.PutUint32(ofw[0:], 0x48000020)
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{name: "algol68", data: []byte("(input, x)\n"), msg: "Algol 68 source, ASCII text"},
		{name: "apl", data: []byte{0, 0, 0x81, 0x6c}, msg: "APL workspace (Ken's original?)"},
		{name: "assembler", data: []byte("\t.globl main\n"), msg: "assembler source, ASCII text"},
		{name: "clarion", data: append([]byte{0x43, 0x33}, make([]byte, 16)...), msg: "Clarion Developer (v2 and above) data file, 0 records"},
		{name: "clipper", data: []byte{0x01, 0x7d}, msg: "CLIPPER COFF executable (VAX #)"},
		{name: "clojure", data: []byte("(ns foo.bar)\n"), msg: "Clojure module source, ASCII text"},
		{name: "erlang", data: append(append([]byte("FOR1"), make([]byte, 4)...), []byte("BEAM")...), msg: "Erlang BEAM file"},
		{name: "etf", data: []byte{131, 97, 1}, msg: "Erlang External Term Format, starts with SMALL_INTEGER_EXT"},
		{name: "forth", data: ofw, msg: "PowerPC OpenFirmware FORTH Dictionary, Text length: 0 bytes, Data length: 0 bytes, BSS length: 0 bytes, Symbol Table length: 0 bytes, Entry Point: 00000000, Text Relocation Table length: 0 bytes, Data Relocation Table length: 0 bytes"},
		{name: "inform", data: []byte("Constant Story \"Hi\"\n"), msg: "Inform source, ASCII text"},
		{name: "lex", data: []byte("/* generated by flex */\n"), msg: "C program text (from flex), ASCII text"},
		{name: "m4", data: []byte("dnl hello\n"), msg: "M4 macro processor script, ASCII text"},
		{name: "maple", data: []byte("\x00MVR4\nI"), msg: "Maple Vr4 library"},
		{name: "mathematica", data: []byte{0x34, 0x14, 0x0a, 0x00, 0x1d, 0, 0, 0}, msg: "Mathematica notebook version 2.x"},
		{name: "nim", data: []byte("import os\nproc foo() =\nwhen true:\n"), msg: "Nim source code, ASCII text"},
		{name: "ocaml", data: []byte("Caml1999X001"), msg: "OCaml exec file (Version 001)"},
		{name: "parrot", data: append([]byte("\376PBC\r\n\032\n"), make([]byte, 80)...), msg: "Parrot bytecode 0.0, little-endian, IEEE-754 8 byte double floats, Parrot 0.0.0"},
		{name: "polyml", data: append([]byte("POLYSAVE"), 0, 0, 0, 1), msg: "Poly/ML saved state version 1"},
		{name: "r", data: []byte("RDA2\nA\n2\n"), msg: "R RData version 2 (ASCII), R RDS (ASCII format v2)"},
		{name: "smalltalk", data: []byte("GSTIm\x00\x00\x00\x01\x02\x03"), msg: "GNU SmallTalk LE image version 3.2.1"},
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
