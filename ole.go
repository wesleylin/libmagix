package libmagix

import (
	"encoding/binary"
	"unicode/utf16"
)

// file reads compound documents before the magic rules. A Hangul 5 file
// stores "HWP Document File" in the FileHeader stream, and that check is
// what the vendored result records.
const hwp5Message = "Hancom HWP (Hangul Word Processor) file, version 5.0"

var oleMagic = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}

func hwp5Document(data []byte) (string, bool) {
	stream, ok := oleStream(data, "FileHeader")
	if !ok || len(stream) < len("HWP Document File") {
		return "", false
	}
	if string(stream[:len("HWP Document File")]) != "HWP Document File" {
		return "", false
	}
	return hwp5Message, true
}

// oleStream returns the bytes of a named stream in an OLE2 compound file.
// Streams smaller than the mini-stream cutoff are read through the root storage.
func oleStream(data []byte, name string) ([]byte, bool) {
	if len(data) < 512 || string(data[:8]) != string(oleMagic) {
		return nil, false
	}
	if binary.LittleEndian.Uint16(data[0x1c:0x1e]) != 0xfffe {
		return nil, false
	}
	secShift := binary.LittleEndian.Uint16(data[0x1e : 0x1e+2])
	miniShift := binary.LittleEndian.Uint16(data[0x20:0x22])
	if secShift < 9 || secShift > 12 || miniShift < 6 || miniShift > secShift {
		return nil, false
	}
	secSize := 1 << secShift
	miniSize := 1 << miniShift
	dirFirst := int32(binary.LittleEndian.Uint32(data[0x30:0x34]))
	cutoff := binary.LittleEndian.Uint32(data[0x38:0x3c])
	miniFATFirst := int32(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	miniFATCount := binary.LittleEndian.Uint32(data[0x40:0x44])

	fat := readFAT(data, secSize)
	if fat == nil {
		return nil, false
	}
	dir := readChain(data, secSize, fat, dirFirst, 0)
	if len(dir) < 128 {
		return nil, false
	}

	var rootStart int32 = -2
	var rootSize uint64
	var streamStart int32 = -2
	var streamSize uint64
	for off := 0; off+128 <= len(dir); off += 128 {
		ent := dir[off : off+128]
		if ent[66] == 0 {
			continue
		}
		n := utf16Name(ent)
		start := int32(binary.LittleEndian.Uint32(ent[116:120]))
		size := binary.LittleEndian.Uint64(ent[120:128])
		if ent[66] == 5 && n == "Root Entry" {
			rootStart = start
			rootSize = size
		}
		if ent[66] == 2 && n == name {
			streamStart = start
			streamSize = size
		}
	}
	if streamStart < 0 || streamSize == 0 || streamSize > 1<<20 {
		return nil, false
	}
	if streamSize >= uint64(cutoff) {
		return readChain(data, secSize, fat, streamStart, int(streamSize)), true
	}
	if rootStart < 0 || rootSize == 0 || rootSize > 1<<24 || miniFATCount == 0 {
		return nil, false
	}
	miniFAT := readChain(data, secSize, fat, miniFATFirst, int(miniFATCount)*secSize)
	container := readChain(data, secSize, fat, rootStart, int(rootSize))
	return readMini(container, miniFAT, miniSize, streamStart, int(streamSize)), true
}

func readFAT(data []byte, secSize int) []int32 {
	if 0x4c+109*4 > len(data) {
		return nil
	}
	var fat []int32
	for i := 0; i < 109; i++ {
		id := int32(binary.LittleEndian.Uint32(data[0x4c+i*4:]))
		if id < 0 {
			continue
		}
		sec := sector(data, secSize, id)
		if sec == nil {
			return nil
		}
		for j := 0; j+4 <= len(sec); j += 4 {
			fat = append(fat, int32(binary.LittleEndian.Uint32(sec[j:])))
		}
	}
	if len(fat) == 0 {
		return nil
	}
	return fat
}

func readChain(data []byte, secSize int, table []int32, start int32, max int) []byte {
	var out []byte
	seen := map[int32]bool{}
	for id := start; id >= 0; {
		if seen[id] || len(seen) > 4096 {
			break
		}
		seen[id] = true
		sec := sector(data, secSize, id)
		if sec == nil {
			break
		}
		out = append(out, sec...)
		if max > 0 && len(out) >= max {
			return out[:max]
		}
		if int(id) >= len(table) {
			break
		}
		id = table[id]
	}
	return out
}

func readMini(container, miniFAT []byte, miniSize int, start int32, max int) []byte {
	if miniSize <= 0 || len(miniFAT) < 4 {
		return nil
	}
	var out []byte
	seen := map[int32]bool{}
	for id := start; id >= 0; {
		if seen[id] || len(seen) > 4096 {
			break
		}
		seen[id] = true
		off := int(id) * miniSize
		if off < 0 || off+miniSize > len(container) {
			break
		}
		out = append(out, container[off:off+miniSize]...)
		if max > 0 && len(out) >= max {
			return out[:max]
		}
		pos := int(id) * 4
		if pos < 0 || pos+4 > len(miniFAT) {
			break
		}
		id = int32(binary.LittleEndian.Uint32(miniFAT[pos:]))
	}
	return out
}

func sector(data []byte, secSize int, id int32) []byte {
	if id < 0 || secSize <= 0 {
		return nil
	}
	off := int(id+1) * secSize
	if off < 0 || off+secSize > len(data) {
		return nil
	}
	return data[off : off+secSize]
}

func utf16Name(ent []byte) string {
	n := int(binary.LittleEndian.Uint16(ent[64:66]))
	if n < 2 || n > 64 || n > len(ent) {
		return ""
	}
	raw := ent[:n-2] // drop the trailing UTF-16 NUL
	if len(raw)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return string(utf16.Decode(u))
}
