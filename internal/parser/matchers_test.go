package parser

import (
	"testing"
)

func TestMatchString(t *testing.T) {
	// note there is the Rule.offset which is the base offset
	// and also the offset parameter inherited
	tests := []struct {
		name       string
		data       []byte
		rule       Rule
		offset     int64
		wantMatch  bool
		wantOffset int64
	}{
		{
			name: "Exact match at offset 0",
			data: []byte("GIF89a test data"),
			rule: Rule{
				Offset:      0,
				Type:        "string",
				Value:       "GIF89a",
				SearchRange: -1,
			},
			wantMatch:  true,
			wantOffset: 6,
		},
		{
			name: "String match not found",
			data: []byte("JFIF test data"),
			rule: Rule{
				Offset: 0,
				Type:   "string",
				Value:  "GIF89a",
			},
			wantMatch:  false,
			wantOffset: 3,
		},
		{
			name: "Partial match (prefix matches)",
			data: []byte("GIF test data"),
			rule: Rule{
				Offset: 0,
				Type:   "string",
				Value:  "GIF",
			},
			wantMatch:  true,
			wantOffset: 3,
		},
		{
			name: "Negative offset (out of bounds)",
			data: []byte("test data"),
			rule: Rule{
				Offset: 0,
				Type:   "string",
				Value:  "test",
			},
			offset:     -1,
			wantMatch:  false,
			wantOffset: 0,
		},
		{
			name: "Offset out of bounds (too large)",
			data: []byte("short"),
			rule: Rule{
				Offset: 100,
				Type:   "string",
				Value:  "test",
			},
			wantMatch:  false,
			wantOffset: 0,
		},
		{
			name: "Empty value string matches anywhere",
			data: []byte("anything goes here"),
			rule: Rule{
				Offset: 0,
				Type:   "string",
				Value:  "",
			},
			wantMatch:  true,
			wantOffset: 0,
		},
		{
			name: "String value is not a string type (should fail)",
			data: []byte("test"),
			rule: Rule{
				Offset: 0,
				Type:   "string",
				Value:  12345, // integer instead of string
			},
			wantMatch:  false,
			wantOffset: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotOffset := matchString(tt.data, &tt.rule, tt.offset)
			if gotMatch != tt.wantMatch {
				t.Errorf("matchString() = %v, want %v for data=%s, rule.Value=%v", gotMatch, tt.wantMatch, tt.data, tt.rule.Value)
			}
			if tt.wantMatch && gotOffset != tt.wantOffset {
				t.Errorf("matchString() offset = %v, want %v", gotOffset, tt.wantOffset)
			}
		})
	}
}

func TestMatchPString(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		rule       Rule
		offset     int64
		wantMatch  bool
		wantOffset int64
	}{
		{
			name:       "1-Byte Length Header (B)",
			data:       []byte{0x04, 't', 'e', 's', 't'},
			rule:       Rule{PStringLengthType: "B", Value: "test"},
			offset:     0,
			wantMatch:  true,
			wantOffset: 5,
		},
		{
			name:       "2-Byte LE Length Header (h)",
			data:       []byte{0x04, 0x00, 't', 'e', 's', 't'},
			rule:       Rule{PStringLengthType: "h", Value: "es"},
			offset:     0,
			wantMatch:  true,
			wantOffset: 6,
		},
		{
			name:       "Buffer Underflow Safe check",
			data:       []byte{0x02},
			rule:       Rule{PStringLengthType: "h", Value: "test"},
			offset:     0,
			wantMatch:  false,
			wantOffset: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotOffset := matchPString(tt.data, &tt.rule, tt.offset)
			if gotMatch != tt.wantMatch || gotOffset != tt.wantOffset {
				t.Errorf("matchPString() = (%v, %v), want (%v, %v)", gotMatch, gotOffset, tt.wantMatch, tt.wantOffset)
			}
		})
	}
}

func TestMatchUTF16BE(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		rule       Rule
		wantMatch  bool
		wantOffset int64
	}{
		{
			name: "bestring16 match 'ABC'",
			data: []byte{0x00, 'A', 0x00, 'B', 0x00, 'C'},
			rule: Rule{
				Offset: 0,
				Type:   "bestring16",
				Value:  "ABC",
			},
			wantMatch:  true,
			wantOffset: 6,
		},
		{
			name: "bestring16 match 'AB'",
			data: []byte{0x00, 'A', 0x00, 'B', 0x00, 'C', 0x00, 'D'},
			rule: Rule{
				Offset: 0,
				Type:   "bestring16",
				Value:  "AB",
			},
			wantMatch:  true,
			wantOffset: 4,
		},
		{
			name: "bestring16 - pattern not found",
			data: []byte{0x00, 'A', 0x00, 'B', 0x00, 'C'},
			rule: Rule{
				Offset: 0,
				Type:   "bestring16",
				Value:  "XYZ",
			},
			wantMatch:  false,
			wantOffset: 0,
		},
		{
			name: "bestring16 - Unicode character U+0041",
			data: []byte{0x00, 'A'}, // Single ASCII char encoded as UTF-16BE
			rule: Rule{
				Offset: 0,
				Type:   "bestring16",
				Value:  "A",
			},
			wantMatch:  true,
			wantOffset: 2,
		},
		{
			name: "bestring16 - offset out of bounds",
			data: []byte{0x00, 'A', 0x00, 'B'},
			rule: Rule{
				Offset: 100,
				Type:   "bestring16",
				Value:  "ABC",
			},
			wantMatch:  false,
			wantOffset: 0,
		},
		{
			name: "bestring16 - invalid value type",
			data: []byte{0x00, 'A', 0x00, 'B'},
			rule: Rule{
				Offset: 0,
				Type:   "bestring16",
				Value:  12345, // not a string
			},
			wantMatch:  false,
			wantOffset: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotOffset := matchUTF16BE(tt.data, &tt.rule, 0)
			if gotMatch != tt.wantMatch {
				t.Errorf("matchUTF16BE() = %v, want %v for data=%v", gotMatch, tt.wantMatch, tt.data)
			}
			if tt.wantMatch && gotOffset != tt.wantOffset {
				t.Errorf("matchUTF16BE() offset = %v, want %v", gotOffset, tt.wantOffset)
			}
		})
	}
}

// func TestMatchSearch(t *testing.T) {
// 	tests := []struct {
// 		name       string
// 		data       []byte
// 		rule       Rule
// 		wantMatch  bool
// 		wantOffset int64
// 	}{
// 		{
// 			name: "search match found at offset 0",
// 			data: []byte("FOUND in the middle"),
// 			rule: Rule{
// 				Offset:      0,
// 				Type:        "search",
// 				Value:       "FOUND",
// 				SearchRange: 20,
// 			},
// 			wantMatch:  true,
// 			wantOffset: 0,
// 		},
// 		{
// 			name: "search match found at non-zero offset",
// 			data: []byte("---FOUND---"),
// 			rule: Rule{
// 				Offset:      0,
// 				Type:        "search",
// 				Value:       "FOUND",
// 				SearchRange: 20,
// 			},
// 			wantMatch:  true,
// 			wantOffset: 4,
// 		},
// 		{
// 			name: "search match not found (out of range)",
// 			data: []byte("---FOUND---"),
// 			rule: Rule{
// 				Offset:      0,
// 				Type:        "search",
// 				Value:       "FOUND",
// 				SearchRange: 5, // Can only search first 5 bytes "---FO", FOUND is at offset 3 which is within range but let's adjust
// 			},
// 			wantMatch:  true, // Actually FOUND starts at offset 3, and range 5 covers [0:5], so it should match
// 			wantOffset: 4,
// 		},
// 		{
// 			name: "search match not found (pattern exists but outside search range)",
// 			data: []byte("---FOUND---"),
// 			rule: Rule{
// 				Offset:      0,
// 				Type:        "search",
// 				Value:       "FOUND",
// 				SearchRange: 3, // Can only search first 3 bytes "---", FOUND is at offset 3 (outside)
// 			},
// 			wantMatch:  false,
// 			wantOffset: 0,
// 		},
// 		{
// 			name: "search match not found (pattern doesn't exist)",
// 			data: []byte("NO MATCH HERE"),
// 			rule: Rule{
// 				Offset:      0,
// 				Type:        "search",
// 				Value:       "FOUND",
// 				SearchRange: 20,
// 			},
// 			wantMatch:  false,
// 			wantOffset: 0,
// 		},
// 		{
// 			name: "search - empty pattern matches at offset",
// 			data: []byte("any data here"),
// 			rule: Rule{
// 				Offset:      0,
// 				Type:        "search",
// 				Value:       "",
// 				SearchRange: 20,
// 			},
// 			wantMatch:  true, // Index finds empty string at position 0
// 			wantOffset: 0,
// 		},
// 		{
// 			name: "search with negative offset (out of bounds)",
// 			data: []byte("test data"),
// 			rule: Rule{
// 				Offset:      -1,
// 				Type:        "search",
// 				Value:       "test",
// 				SearchRange: 20,
// 			},
// 			wantMatch:  false,
// 			wantOffset: 0,
// 		},
// 		{
// 			name: "search offset out of bounds (too large)",
// 			data: []byte("short"),
// 			rule: Rule{
// 				Offset:      100,
// 				Type:        "search",
// 				Value:       "test",
// 				SearchRange: 20,
// 			},
// 			wantMatch:  false,
// 			wantOffset: 0,
// 		},
// 	}

//		for _, tt := range tests {
//			t.Run(tt.name, func(t *testing.T) {
//				gotMatch, gotOffset := matchSearch(tt.data, &tt.rule, 0)
//				if gotMatch != tt.wantMatch {
//					t.Errorf("matchSearch() = %v, want %v for data=%s, rule.SearchRange=%d", gotMatch, tt.wantMatch, tt.data, tt.rule.SearchRange)
//				}
//				if tt.wantMatch && gotOffset != tt.wantOffset {
//					t.Errorf("matchSearch() offset = %v, want %v", gotOffset, tt.wantOffset)
//				}
//			})
//		}
//	}

func TestMatchByte(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		rule       Rule
		offset     int64 // Explicit execution cursor state for testing runtime calls
		wantMatch  bool
		wantOffset int64
	}{
		{
			name: "Exact match at offset 0",
			data: []byte{0x41}, // 'A'
			rule: Rule{
				Type:  "byte",
				Value: uint8(0x41),
			},
			offset:     0,
			wantMatch:  true,
			wantOffset: 1, // matchByte returns offset + 1 on success
		},
		{
			name: "Greater than match",
			data: []byte{0x41}, // 'A' = 65
			rule: Rule{
				Type:     "byte",
				Value:    uint8(0x40), // 'A' > '@' (64)
				Operator: ">",
			},
			offset:     0,
			wantMatch:  true,
			wantOffset: 1,
		},
		{
			name: "Less than match",
			data: []byte{0x41}, // 'A' = 65
			rule: Rule{
				Type:     "byte",
				Value:    uint8(0x42), // 'B' = 66
				Operator: "<",
			},
			offset:     0,
			wantMatch:  true,
			wantOffset: 1,
		},
		{
			name: "Not equal match",
			data: []byte{0x41}, // 'A' = 65
			rule: Rule{
				Type:     "byte",
				Value:    uint8(0x42), // 'B' = 66
				Operator: "!",
			},
			offset:     0,
			wantMatch:  true,
			wantOffset: 1,
		},
		{
			name: "Bitwise AND operator",
			data: []byte{0x07}, // 0111 in binary
			rule: Rule{
				Type:     "byte",
				Value:    uint8(0x03), // 0011 in binary
				Operator: "&",
			},
			offset:     0,
			wantMatch:  true,
			wantOffset: 1,
		},
		{
			name: "Bitwise NOT operator (^)",
			data: []byte{0x7F}, // 01111111 in binary
			rule: Rule{
				Type:     "byte",
				Value:    uint8(0x80), // 10000000 in binary
				Operator: "^",
			},
			offset:     0,
			wantMatch:  true,
			wantOffset: 1,
		},
		{
			name: "Bitmasking with HasMask",
			data: []byte{0x81}, // 10000001
			rule: Rule{
				Type:     "byte",
				Value:    uint8(0x80),
				Mask:     0xFF00,
				HasMask:  true,
				Operator: "=",
			},
			offset:     0,
			wantMatch:  true, // (0x81 & 0xF0) -> 0x80 == (0x80 & 0xF0) -> 0x80. Match!
			wantOffset: 1,
		},
		{
			name: "Bitmasking with HasMask (correct)",
			data: []byte{0x81}, // 10000001
			rule: Rule{
				Type:     "byte",
				Value:    uint8(0x01), // matches lower bit
				Mask:     0xFF,        // mask keeps all bits
				HasMask:  true,
				Operator: "&",
			},
			offset:     0,
			wantMatch:  true, // (0x81 & 0x01) == 0x01. Match!
			wantOffset: 1,
		},
		{
			name: "Bitmasking AND operator",
			data: []byte{0x81}, // 10000001
			rule: Rule{
				Type:     "byte",
				Value:    uint8(0x80),
				Mask:     0xFF,
				HasMask:  true,
				Operator: "&",
			},
			offset:     0,
			wantMatch:  true,
			wantOffset: 1,
		},
		{
			name: "Match with default operator (=)",
			data: []byte{0x41},
			rule: Rule{
				Type:     "ubyte",
				Value:    uint8(0x41),
				Operator: "=",
			},
			offset:     0,
			wantMatch:  true,
			wantOffset: 1,
		},
		{
			name: "Negative offset (out of bounds)",
			data: []byte("test"),
			rule: Rule{
				Type:  "byte",
				Value: uint8(0x41),
			},
			offset:     -1,
			wantMatch:  false,
			wantOffset: 0,
		},
		{
			name: "Offset out of bounds (too large)",
			data: []byte("short"),
			rule: Rule{
				Type:  "byte",
				Value: uint8(0x41),
			},
			offset:     100,
			wantMatch:  false,
			wantOffset: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pass tt.offset directly into your handler function
			gotMatch, gotOffset := matchByte(tt.data, &tt.rule, tt.offset)

			if gotMatch != tt.wantMatch {
				t.Errorf("matchByte() match = %v, want %v for data=%v at offset=%d", gotMatch, tt.wantMatch, tt.data, tt.offset)
			}
			if tt.wantMatch && gotOffset != tt.wantOffset {
				t.Errorf("matchByte() advanced offset = %v, want %v", gotOffset, tt.wantOffset)
			}
		})
	}
}

func TestMatchShortLE(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		rule       Rule
		wantMatch  bool
		wantOffset int64
	}{
		{
			name: "match uint16 value 0x1234",
			data: []byte{0x34, 0x12}, // Little-endian: low byte first (0x34), then high byte (0x12)
			rule: Rule{
				Offset: 0,
				Type:   "leshort",
				Value:  uint16(0x1234),
			},
			wantMatch:  true,
			wantOffset: 2,
		},
		{
			name: "match with greater than operator",
			data: []byte{0x50, 0x02}, // 0x0250 = 592 in little-endian
			rule: Rule{
				Offset:   0,
				Type:     "leshort",
				Value:    uint16(0x0200), // 512
				Operator: ">",
			},
			wantMatch:  true, // 592 > 512
			wantOffset: 2,
		},
		{
			name: "match with less than operator",
			data: []byte{0x30, 0x01}, // 0x0130 = 304 in little-endian
			rule: Rule{
				Offset:   0,
				Type:     "leshort",
				Value:    uint16(0x0200), // 512
				Operator: "<",
			},
			wantMatch:  true, // 304 < 512
			wantOffset: 2,
		},
		{
			name: "match with bitwise AND operator",
			data: []byte{0x07, 0x00}, // 0x0007 = 7 in little-endian
			rule: Rule{
				Offset:   0,
				Type:     "leshort",
				Value:    uint16(0x03), // 3 in little-endian (same value)
				Operator: "&",
			},
			wantMatch:  true, // (7 & 3) == 3
			wantOffset: 2,
		},
		{
			name: "match with bitwise NOT operator (^)",
			data: []byte{0x7F, 0x00}, // 0x00FF = 255 in little-endian
			rule: Rule{
				Offset:   0,
				Type:     "leshort",
				Value:    uint16(0x80), // 128
				Operator: "^",
			},
			wantMatch:  true, // (255 & 128) == 0
			wantOffset: 2,
		},
		{
			name: "Bitmasking with HasMask",
			data: []byte{0x81, 0xFF}, // 0xFF81 in LE = 65313
			rule: Rule{
				Offset:  0,
				Type:    "leshort",
				Value:   uint16(0x01), // lower bit
				Mask:    0xFFFF00,     // mask keeps upper bits
				HasMask: true,
			},
			wantMatch:  false, // (0xFF81 & 0xFFFF00) = 0xF800 != 0x0001
			wantOffset: 0,
		},
		{
			name: "Bitmasking with HasMask (correct)",
			data: []byte{0x81, 0xFF}, // 0xFF81 in LE
			rule: Rule{
				Offset:  0,
				Type:    "leshort",
				Value:   uint16(0x80), // upper bit
				Mask:    0xFF,         // keeps lower bits
				HasMask: true,
			},
			wantMatch:  false, // (0xFF81 & 0xFF) = 0x81 != 0x80
			wantOffset: 0,
		},
		{
			name: "Data too short for short (2 bytes)",
			data: []byte("A"),
			rule: Rule{
				Offset: 0,
				Type:   "leshort",
				Value:  uint16(0x1234),
			},
			wantMatch:  false,
			wantOffset: 0,
		},
		{
			name: "Negative offset (out of bounds)",
			data: []byte("test"),
			rule: Rule{
				Offset: -2,
				Type:   "leshort",
				Value:  uint16(0x1234),
			},
			wantMatch:  false,
			wantOffset: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotOffset := matchShortLE(tt.data, &tt.rule, 0)
			if gotMatch != tt.wantMatch {
				t.Errorf("matchShortLE() = %v, want %v for data=%v", gotMatch, tt.wantMatch, tt.data)
			}
			if tt.wantMatch && gotOffset != tt.wantOffset {
				t.Errorf("matchShortLE() offset = %v, want %v", gotOffset, tt.wantOffset)
			}
		})
	}
}

func TestMatchShortBE(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		rule       Rule
		wantMatch  bool
		wantOffset int64
	}{
		{
			name: "match uint16 value 0x1234 (big-endian)",
			data: []byte{0x12, 0x34}, // Big-endian: high byte first (0x12), then low byte (0x34)
			rule: Rule{
				Offset: 0,
				Type:   "beshort",
				Value:  uint16(0x1234),
			},
			wantMatch:  true,
			wantOffset: 2,
		},
		{
			name: "match with greater than operator",
			data: []byte{0x02, 0x50}, // 0x0250 = 592 in big-endian
			rule: Rule{
				Offset:   0,
				Type:     "beshort",
				Value:    uint16(0x0200), // 512
				Operator: ">",
			},
			wantMatch:  true, // 592 > 512
			wantOffset: 2,
		},
		{
			name: "match with less than operator",
			data: []byte{0x01, 0x30}, // 0x0130 = 304 in big-endian
			rule: Rule{
				Offset:   0,
				Type:     "beshort",
				Value:    uint16(0x0200), // 512
				Operator: "<",
			},
			wantMatch:  true, // 304 < 512
			wantOffset: 2,
		},
		{
			name: "Data too short for short (2 bytes)",
			data: []byte("A"),
			rule: Rule{
				Offset: 0,
				Type:   "beshort",
				Value:  uint16(0x1234),
			},
			wantMatch:  false,
			wantOffset: 0,
		},
		{
			name: "Negative offset (out of bounds)",
			data: []byte("test"),
			rule: Rule{
				Offset: -2,
				Type:   "beshort",
				Value:  uint16(0x1234),
			},
			wantMatch:  false,
			wantOffset: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotOffset := matchShortBE(tt.data, &tt.rule, 0)
			if gotMatch != tt.wantMatch {
				t.Errorf("matchShortBE() = %v, want %v for data=%v", gotMatch, tt.wantMatch, tt.data)
			}
			if tt.wantMatch && gotOffset != tt.wantOffset {
				t.Errorf("matchShortBE() offset = %v, want %v", gotOffset, tt.wantOffset)
			}
		})
	}
}

func TestMatchLongLE(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		rule       Rule
		wantMatch  bool
		wantOffset int64
	}{
		{
			name: "match uint32 value 0x12345678 (little-endian)",
			data: []byte{0x78, 0x56, 0x34, 0x12}, // LE: low bytes first
			rule: Rule{
				Offset: 0,
				Type:   "lelong",
				Value:  uint32(0x12345678),
			},
			wantMatch:  true,
			wantOffset: 4,
		},
		{
			name: "match with greater than operator",
			data: []byte{0x90, 0xAB, 0xCD, 0xEF}, // 0xEFCDAB90 in LE = huge value
			rule: Rule{
				Offset:   0,
				Type:     "lelong",
				Value:    uint32(0x12345678),
				Operator: ">",
			},
			wantMatch:  true, // Large LE value > smaller value
			wantOffset: 4,
		},
		{
			name: "match with bitwise AND operator",
			data: []byte{0x07, 0x00, 0x00, 0x00}, // 0x00000007 = 7 in LE
			rule: Rule{
				Offset:   0,
				Type:     "lelong",
				Value:    uint32(0x03), // 3 in LE
				Operator: "&",
			},
			wantMatch:  true, // (7 & 3) == 3
			wantOffset: 4,
		},
		{
			name: "Data too short for long (4 bytes)",
			data: []byte("test"),
			rule: Rule{
				Offset: 0,
				Type:   "lelong",
				Value:  uint32(0x12345678),
			},
			wantMatch:  false,
			wantOffset: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotOffset := matchLongLE(tt.data, &tt.rule, 0)
			if gotMatch != tt.wantMatch {
				t.Errorf("matchLongLE() = %v, want %v for data=%v", gotMatch, tt.wantMatch, tt.data)
			}
			if tt.wantMatch && gotOffset != tt.wantOffset {
				t.Errorf("matchLongLE() offset = %v, want %v", gotOffset, tt.wantOffset)
			}
		})
	}
}

func TestMatchLongBE(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		rule       Rule
		wantMatch  bool
		wantOffset int64
	}{
		{
			name: "match uint32 value 0x12345678 (big-endian)",
			data: []byte{0x12, 0x34, 0x56, 0x78}, // BE: high bytes first
			rule: Rule{
				Offset: 0,
				Type:   "belong",
				Value:  uint32(0x12345678),
			},
			wantMatch:  true,
			wantOffset: 4,
		},
		{
			name: "match with bitwise AND operator",
			data: []byte{0x00, 0x00, 0x00, 0x07}, // 0x00000007 = 7 in BE
			rule: Rule{
				Offset:   0,
				Type:     "belong",
				Value:    uint32(0x03), // 3 in BE
				Operator: "&",
			},
			wantMatch:  true, // (7 & 3) == 3
			wantOffset: 4,
		},
		{
			name: "Data too short for long (4 bytes)",
			data: []byte("test"),
			rule: Rule{
				Offset: 0,
				Type:   "belong",
				Value:  uint32(0x12345678),
			},
			wantMatch:  false,
			wantOffset: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotOffset := matchLongBE(tt.data, &tt.rule, 0)
			if gotMatch != tt.wantMatch {
				t.Errorf("matchLongBE() = %v, want %v for data=%v", gotMatch, tt.wantMatch, tt.data)
			}
			if tt.wantMatch && gotOffset != tt.wantOffset {
				t.Errorf("matchLongBE() offset = %v, want %v", gotOffset, tt.wantOffset)
			}
		})
	}
}

func TestMatchNumericHandler(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		rule       Rule
		wantMatch  bool
		wantOffset int64
	}{
		{
			name: "ulelong (unsigned little-endian long) match",
			data: []byte{0x78, 0x56, 0x34, 0x12},
			rule: Rule{
				Offset: 0,
				Type:   "ulelong",
				Value:  uint32(0x12345678),
			},
			wantMatch:  true,
			wantOffset: 4,
		},
		{
			name: "leshort (unsigned little-endian short) match",
			data: []byte{0x34, 0x12},
			rule: Rule{
				Offset: 0,
				Type:   "uleshort",
				Value:  uint16(0x1234),
			},
			wantMatch:  true,
			wantOffset: 2,
		},
		{
			name: "belong (unsigned big-endian long) match",
			data: []byte{0x12, 0x34, 0x56, 0x78},
			rule: Rule{
				Offset: 0,
				Type:   "ubelong",
				Value:  uint32(0x12345678),
			},
			wantMatch:  true,
			wantOffset: 4,
		},
		{
			name: "ubeshort (unsigned big-endian short) match",
			data: []byte{0x12, 0x34},
			rule: Rule{
				Offset: 0,
				Type:   "ubeshort",
				Value:  uint16(0x1234),
			},
			wantMatch:  true,
			wantOffset: 2,
		},
		{
			name: "byte match",
			data: []byte{0x41},
			rule: Rule{
				Offset: 0,
				Type:   "byte",
				Value:  uint8(0x41),
			},
			wantMatch:  true,
			wantOffset: 1,
		},
		{
			name: "Data too short for type",
			data: []byte("test"),
			rule: Rule{
				Offset: 0,
				Type:   "belong",
				Value:  uint32(0x12345678),
			},
			wantMatch:  false,
			wantOffset: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch, gotOffset := matchNumericHandler(tt.data, &tt.rule, 0)
			if gotMatch != tt.wantMatch {
				t.Errorf("matchNumericHandler() = %v, want %v for data=%v", gotMatch, tt.wantMatch, tt.data)
			}
			if tt.wantMatch && gotOffset != tt.wantOffset {
				t.Errorf("matchNumericHandler() offset = %v, want %v", gotOffset, tt.wantOffset)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		name      string
		actual    uint64
		expected  uint64
		op        string
		wantMatch bool
	}{
		{
			name:      "Equal operator",
			actual:    10,
			expected:  10,
			op:        "=",
			wantMatch: true,
		},
		{
			name:      "Not equal operator",
			actual:    10,
			expected:  20,
			op:        "!",
			wantMatch: true,
		},
		{
			name:      "Greater than operator",
			actual:    20,
			expected:  10,
			op:        ">",
			wantMatch: true,
		},
		{
			name:      "Less than operator",
			actual:    10,
			expected:  20,
			op:        "<",
			wantMatch: true,
		},
		{
			name:      "Bitwise AND operator (all bits set)",
			actual:    7, // 0111
			expected:  3, // 0011
			op:        "&",
			wantMatch: true, // (7 & 3) == 3
		},
		{
			name:      "Bitwise AND operator (not all bits set)",
			actual:    5, // 0101
			expected:  3, // 0011
			op:        "&",
			wantMatch: false, // (5 & 3) = 1 != 3
		},
		{
			name:      "Bitwise NOT operator (^)",
			actual:    255, // 11111111
			expected:  128, // 10000000
			op:        "^",
			wantMatch: false, // (255 & 128) == 0
		},
		{
			name:      "Bitwise NOT operator (^) - Successful Match",
			actual:    127, // 01111111 (bit 128 is clean)
			expected:  128, // 10000000
			op:        "^",
			wantMatch: true, // (127 & 128) is 0, and 0 != 128 is true!
		},
		{
			name:      "Default operator (=)",
			actual:    10,
			expected:  10,
			op:        "=",
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch := compare(tt.actual, tt.expected, tt.op)
			if gotMatch != tt.wantMatch {
				t.Errorf("compare(%d, %d, %s) = %v, want %v", tt.actual, tt.expected, tt.op, gotMatch, tt.wantMatch)
			}
		})
	}
}

func TestCastToUint64(t *testing.T) {
	tests := []struct {
		name       string
		input      any
		wantResult uint64
	}{
		{
			name:       "uint64 value",
			input:      uint64(0x12345678),
			wantResult: 0x12345678,
		},
		{
			name:       "uint32 value",
			input:      uint32(0x12345678),
			wantResult: 0x12345678,
		},
		{
			name:       "uint16 value",
			input:      uint16(0x1234),
			wantResult: 0x1234,
		},
		{
			name:       "uint8 value",
			input:      uint8(0x41),
			wantResult: 0x41,
		},
		{
			name:       "int value",
			input:      int(-128),
			wantResult: 0xffffffffffffff80, // -128 as uint64
		},
		{
			name:       "int32 value",
			input:      int32(-1),
			wantResult: 0xFFFFFFFF, // -1 as uint64 (low bits)
		},
		{
			name:       "int64 value",
			input:      int64(-1),
			wantResult: 0xFFFFFFFFFFFFFFFF, // -1 as uint64
		},
		{
			name:       "nil input (default case)",
			input:      nil,
			wantResult: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult := castToUint64(tt.input)
			if gotResult != tt.wantResult {
				t.Errorf("castToUint64(%v) = 0x%x, want 0x%x", tt.input, gotResult, tt.wantResult)
			}
		})
	}
}

func TestRule_Match_Byte(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		rule      Rule
		wantMatch bool
	}{
		{
			name: "PNG signature match",
			data: []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
			rule: Rule{
				Offset:   0,
				Type:     "string",
				ValueRaw: []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
			},
			wantMatch: true,
		},
		{
			name: "JPEG signature match",
			data: []byte{0xFF, 0xD8, 0xFF, 0xE1, 'J', 'P', 'E', 'G'},
			rule: Rule{
				Offset:   0,
				Type:     "string",
				ValueRaw: []byte{0xFF, 0xD8},
			},
			wantMatch: true,
		},
		{
			name: "Mismatched signature",
			data: []byte{'G', 'I', 'F', '8'},
			rule: Rule{
				Offset:   0,
				Type:     "string",
				ValueRaw: []byte{0x89, 'P', 'N', 'G'},
			},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch := tt.rule.MatchByte(tt.data)
			if gotMatch != tt.wantMatch {
				t.Errorf("Rule.MatchByte() = %v, want %v for data=%v", gotMatch, tt.wantMatch, tt.data)
			}
		})
	}
}

// Test that all handler functions are registered correctly
func TestHandlerRegistry(t *testing.T) {
	testCases := []struct {
		handlerName string
		data        []byte
		rule        Rule
	}{
		{"string", []byte("test"), Rule{Offset: 0, Type: "string", Value: "test"}},
		{"pstring", []byte{0x04, 'a', 'b', 'c'}, Rule{Offset: 0, Type: "pstring", PStringLengthType: "B", Value: "abc"}},
		{"lestring16", []byte{'A', 0x00, 'B', 0x00}, Rule{Offset: 0, Type: "lestring16", Value: "AB"}},
		{"bestring16", []byte{0x00, 'A', 0x00, 'B'}, Rule{Offset: 0, Type: "bestring16", Value: "AB"}},
		{"search", []byte("FOUND"), Rule{Offset: 0, Type: "search", Value: "FOUND", SearchRange: -1}},
		{"byte", []byte{0x41}, Rule{Offset: 0, Type: "byte", Value: uint8(0x41)}},
		{"leshort", []byte{0x34, 0x12}, Rule{Offset: 0, Type: "leshort", Value: uint16(0x1234)}},
		{"beshort", []byte{0x12, 0x34}, Rule{Offset: 0, Type: "beshort", Value: uint16(0x1234)}},
		{"lelong", []byte{0x78, 0x56, 0x34, 0x12}, Rule{Offset: 0, Type: "lelong", Value: uint32(0x12345678)}},
		{"belong", []byte{0x12, 0x34, 0x56, 0x78}, Rule{Offset: 0, Type: "belong", Value: uint32(0x12345678)}},
	}

	for _, tc := range testCases {
		t.Run(tc.handlerName, func(t *testing.T) {
			handler := getHandler(tc.rule.Type)
			if handler == nil {
				t.Errorf("getHandler() returned nil for type %s", tc.rule.Type)
			} else {
				_, _ = handler(tc.data, &tc.rule, 0)
			}
		})
	}

	// Verify that all handlers are in the global registry
	for name := range handlerMap {
		handler := getHandler(name)
		if handler == nil {
			t.Errorf("getHandler() returned nil for registered type %s", name)
		}
	}
}
