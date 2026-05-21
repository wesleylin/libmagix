package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// Rule represents a single line in a magic file
type Rule struct {
	Level    int
	Offset   int64
	Type     string
	Operator string
	Mask     uint64
	HasMask  bool
	Value    any
	ValueRaw []byte
	Message  string
	Mime     string
	MatchAny bool // Support for 'x' value in magic files

	// Indirect Offset support: (offset.type[+-/*]value)
	IsIndirect    bool
	PointerOffset int64
	PointerType   string
	PointerAdd    int64

	SearchRange int64
	IsRelative  bool // Support for '&' relative offset

	Children []Rule
	RuleName string // For 'name' blocks

	// Pascal String support: pstring/modifier
	PStringLengthType string // 'B', 'H', 'h', 'l', 'L'

	// Indirect Offset Adjustment: (offset.type+adj)
	PointerAdjustment int64
}

func (r Rule) String() string {
	indent := strings.Repeat("> ", r.Level)
	typeDisplay := r.Type
	if r.HasMask {
		typeDisplay = fmt.Sprintf("%s&0x%X", r.Type, r.Mask)
	}
	return fmt.Sprintf("%-10s L%d Off:%-5d %-15s %s %v -> %s",
		indent, r.Level, r.Offset, typeDisplay, r.Operator, r.Value, r.Message)
}

// Match checks if this rule matches the provided data.
// It takes a baseOffset (the match location of the parent rule) to support relative offsets.
// It returns whether it matched and the absolute offset where the match occurred.
func (r *Rule) Match(data []byte, baseOffset int64, forcedRelative bool) (bool, int64) {
	// 1. Resolve the actual offset (handling relative and indirect offsets)
	actualOffset, _ := r.resolveOffset(data, baseOffset, forcedRelative)

	// Handle Meta-types
	if r.Type == "name" {
		return false, 0 // Declarations don't match data
	}
	if r.Type == "use" {
		// 'use' calls always "match" to trigger the jump,
		// and they always use the current baseOffset.
		return true, actualOffset
	}

	// 2. MatchAny 'x' (always matches if within bounds)
	if r.MatchAny {
		if actualOffset < 0 || actualOffset >= int64(len(data)) {
			return false, 0
		}
		return true, actualOffset
	}

	// 3. Delegate to type-specific handlers using registry lookup
	handler, found := handlerMap[r.Type]
	if !found {
		// Default to numeric handling for unknown types
		return matchNumericHandler(data, r, actualOffset)
	}
	return handler(data, r, actualOffset)
}

// getHandler retrieves the handler function for a given type from the registry.
func getHandler(t string) Handler {
	return handlerMap[t]
}

var handlerMap = map[string]Handler{
	"string":     matchString,
	"pstring":    matchPString,
	"lestring16": matchUTF16LE,
	"bestring16": matchUTF16BE,
	"search":     matchSearch,
	"byte":       matchByte,
	"ubyte":      matchByte,
	"leshort":    matchShortLE,
	"beshort":    matchShortBE,
	"uleshort":   matchShortLE,
	"ubeshort":   matchShortBE,
	"lelong":     matchLongLE,
	"belong":     matchLongBE,
	"ulelong":    matchLongLE,
	"ubelong":    matchLongBE,
	"uint16":     matchShortLE,
	"uint32":     matchLongLE,
	"long":       matchLongBE,
}

// resolveOffset calculates the final absolute offset, handling relative (&) and indirect ((...)) syntax.
func (r *Rule) resolveOffset(data []byte, baseOffset int64, forcedRelative bool) (int64, bool) {
	// 0. Initial offset
	absoluteOffset := r.Offset
	if r.IsRelative || forcedRelative {
		absoluteOffset += baseOffset
	}

	// 1. Handle Indirect Offsets (e.g., (0x3c.l))
	actualOffset := absoluteOffset
	if r.IsIndirect {
		ptrOff := r.PointerOffset
		if r.IsRelative || forcedRelative {
			ptrOff += baseOffset
		}

		if ptrOff < 0 || ptrOff >= int64(len(data)) {
			return 0, false
		}

		var pointerVal int64
		switch r.PointerType {
		case "b": // byte
			pointerVal = int64(data[ptrOff])
		case "s": // little-endian short
			if ptrOff+2 > int64(len(data)) {
				return 0, false
			}
			pointerVal = int64(binary.LittleEndian.Uint16(data[ptrOff : ptrOff+2]))
		case "S": // big-endian short
			if ptrOff+2 > int64(len(data)) {
				return 0, false
			}
			pointerVal = int64(binary.BigEndian.Uint16(data[ptrOff : ptrOff+2]))
		case "l": // little-endian long
			if ptrOff+4 > int64(len(data)) {
				return 0, false
			}
			pointerVal = int64(binary.LittleEndian.Uint32(data[ptrOff : ptrOff+4]))
		case "L": // big-endian long
			if ptrOff+4 > int64(len(data)) {
				return 0, false
			}
			pointerVal = int64(binary.BigEndian.Uint32(data[ptrOff : ptrOff+4]))
		}
		actualOffset = pointerVal + r.PointerAdd + r.PointerAdjustment
	}

	return actualOffset, true
}

// MatchByte checks if this rule matches byte-level data (for ValueRaw or Value when it's []byte)
func (r *Rule) MatchByte(data []byte) bool {
	// Use ValueRaw if set, otherwise try to use Value if it's a []byte
	if len(r.ValueRaw) > 0 {
		end := int(r.Offset) + len(r.ValueRaw)
		if r.Offset < 0 || len(data) < end {
			return false
		}
		return bytes.Equal(data[r.Offset:end], r.ValueRaw)
	}

	// Fall back to Value if it's a []byte (for tests and backwards compatibility)
	if valBytes, ok := r.Value.([]byte); ok && len(valBytes) > 0 {
		end := int(r.Offset) + len(valBytes)
		if r.Offset < 0 || len(data) < end {
			return false
		}
		return bytes.Equal(data[r.Offset:end], valBytes)
	}

	return false
}

// String representation of the rule's children
func (r *Rule) childrenString(level int) string {
	var sb strings.Builder
	for _, child := range r.Children {
		sb.WriteString(child.String())
		sb.WriteString("\n")
		if child.RuleName != "" {
			sb.WriteString("  // Rule name: ")
			sb.WriteString(child.RuleName)
			sb.WriteString("\n")
		}
		if level+1 < len(r.Children) && r.Children[level+1].Offset != 0 {
			sb.WriteString("  // Offset from rule definition: ")
			sb.WriteString(fmt.Sprintf("%d", child.Offset))
			sb.WriteString("\n")
		}
	}
	return sb.String()
}
