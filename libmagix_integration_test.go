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

func TestStarOfficeIdentification(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	engine, err := libmagix.New("magic/Magdir/wordprocessorOfficial", logger)
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
	engine, err := libmagix.New("magic/upstream/Magdir", logger)
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
			msg:  "gzip compressed data, from Unix",
			mime: "application/gzip",
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

func TestEasyAllowlistSignatures(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	engine, err := libmagix.New("magic/upstream/Magdir", logger)
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
			rules, err := p.LoadFile(filepath.Join("magic/upstream/Magdir", name))
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
	engine, err := libmagix.New("magic/upstream/Magdir", logger)
	if err != nil {
		t.Fatal(err)
	}
	names := readNameList(t, "testdata/allowlist")
	if len(names) == 0 {
		t.Fatal("testdata/allowlist is empty")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata/upstream", name+".testfile"))
			if err != nil {
				t.Fatal(err)
			}
			wantBytes, err := os.ReadFile(filepath.Join("testdata/upstream", name+".result"))
			if err != nil {
				t.Fatal(err)
			}
			want := strings.TrimRight(string(wantBytes), "\n")
			eng := engine
			if paths, err := filepath.Glob(filepath.Join("testdata/upstream", name+"*.magic")); err == nil && len(paths) > 0 {
				eng, err = libmagix.NewFiles(paths, logger)
				if err != nil {
					t.Fatal(err)
				}
			}
			var got *libmagix.Result
			if continueFlags(filepath.Join("testdata/upstream", name+".flags")) {
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
