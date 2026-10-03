package libmagix

import (
	"log/slog"
	"os"
	"strings"

	"github.com/wesleylin/libmagix/internal/parser"
)

type Magix struct {
	rules      []parser.Rule
	namedRules map[string]*parser.Rule
	logger     *slog.Logger
}

// Result represents the outcome of an identification.
type Result struct {
	Message string
	Mime    string
}

func (r *Result) String() string {
	return r.Message
}

// New loads all magic files from the specified directory.
func New(magicPath string, logger *slog.Logger) (*Magix, error) {
	if logger == nil {
		logger = slog.Default()
	}

	p := parser.NewParser(logger)

	info, err := os.Stat(magicPath)
	if err != nil {
		return nil, err
	}

	var rawRules []parser.Rule
	if info.IsDir() {
		rawRules, err = p.LoadDirectory(magicPath)
	} else {
		rawRules, err = p.LoadFile(magicPath)
	}

	if err != nil {
		return nil, err
	}

	// Separate named rules from main rules
	mainRules := []parser.Rule{}
	namedRules := make(map[string]*parser.Rule)
	for i := range rawRules {
		if rawRules[i].Type == "name" {
			name, ok := rawRules[i].Value.(string)
			if ok {
				namedRules[name] = &rawRules[i]
			}
		} else {
			mainRules = append(mainRules, rawRules[i])
		}
	}

	logger.Debug("Loaded", slog.Int("rules", len(mainRules)), slog.Int("named_blocks", len(namedRules)), slog.String("from", magicPath))
	return &Magix{rules: mainRules, namedRules: namedRules, logger: logger}, nil
}

// Identify takes file bytes and returns a Result containing the full, concatenated description.
func (m *Magix) Identify(data []byte) *Result {
	for i := range m.rules {
		if matched, matchedOffset, val := m.rules[i].MatchValue(data, 0, false); matched {
			var fullMsg strings.Builder
			var lastMime string

			m.identifyRecursive(data, &m.rules[i], 0, matchedOffset, false, val, false, &fullMsg, &lastMime, 0)
			// A level-0 test with an empty description does not count as a hit
			// unless a continuation printed something. libmagic keeps scanning.
			if strings.TrimSpace(fullMsg.String()) == "" && lastMime == "" {
				continue
			}

			return &Result{
				Message: strings.TrimSpace(fullMsg.String()),
				Mime:    lastMime,
			}
		}
	}
	return nil
}

func (m *Magix) identifyRecursive(data []byte, r *parser.Rule, plainBase, relativeBase int64, inUse bool, val any, flip bool, fullMsg *strings.Builder, lastMime *string, depth int) {
	if r.Type == "indirect" {
		appendMagicText(fullMsg, parser.FormatMessage(r.Message, r.Type, val))
		if depth < 2 {
			m.identifyAt(data, relativeBase, fullMsg, lastMime, depth+1)
		}
		m.walk(data, r.Children, plainBase, relativeBase, inUse, flip, fullMsg, lastMime, depth)
		return
	}
	if r.Type == "use" {
		// Continuations of the use line run only after the named block
		// matches. Their relative base is the offset where the use was entered.
		if m.execUse(data, r, relativeBase, flip, fullMsg, lastMime, depth) {
			m.walk(data, r.Children, plainBase, relativeBase, inUse, flip, fullMsg, lastMime, depth)
		}
		return
	}

	if r.Mime != "" {
		*lastMime = r.Mime
	}
	appendMagicText(fullMsg, parser.FormatMessage(r.Message, r.Type, val))

	m.walk(data, r.Children, plainBase, relativeBase, inUse, flip, fullMsg, lastMime, depth)
}

// walk scans rules that share a continuation level.
// default matches only when nothing else at this level has matched.
// clear resets that flag so a later default can still run.
// Inside a subroutine, direct offsets stay relative to plainBase (the use).
// '&' offsets stay relative to relativeBase (the end of the previous match).
func (m *Magix) walk(data []byte, rules []parser.Rule, plainBase, relativeBase int64, inUse, flip bool, fullMsg *strings.Builder, lastMime *string, depth int) bool {
	gotMatch := false
	matchedAny := false
	for i := range rules {
		r := rules[i]
		if r.Type == "default" && gotMatch {
			continue
		}
		if flip {
			r.Type = swapEndianType(r.Type)
			r.PointerType = swapEndianType(r.PointerType)
		}

		base := int64(0)
		forced := false
		if r.IsRelative {
			base = relativeBase
			forced = true
		} else if inUse {
			base = plainBase
			forced = true
		}
		matched, off, val := r.MatchValue(data, base, forced)
		if !matched {
			continue
		}
		if r.Type == "clear" {
			m.identifyRecursive(data, &r, plainBase, off, inUse, val, flip, fullMsg, lastMime, depth)
			gotMatch = false
			continue
		}
		gotMatch = true
		matchedAny = true
		m.identifyRecursive(data, &r, plainBase, off, inUse, val, flip, fullMsg, lastMime, depth)
	}
	return matchedAny
}

// identifyAt runs the top-level tests as if the file began at base.
// indirect rules use this to describe the bytes they point at.
func (m *Magix) identifyAt(data []byte, base int64, fullMsg *strings.Builder, lastMime *string, depth int) {
	for i := range m.rules {
		matched, off, val := m.rules[i].MatchValue(data, base, true)
		if !matched {
			continue
		}
		var nested strings.Builder
		var mime string
		m.identifyRecursive(data, &m.rules[i], base, off, true, val, false, &nested, &mime, depth)
		if strings.TrimSpace(nested.String()) == "" && mime == "" {
			continue
		}
		text := nested.String()
		if text != "" && fullMsg.Len() > 0 && !strings.HasSuffix(fullMsg.String(), " ") && text[0] != ' ' {
			fullMsg.WriteByte(' ')
		}
		fullMsg.WriteString(text)
		if mime != "" {
			*lastMime = mime
		}
		return
	}
}

func (m *Magix) execUse(data []byte, r *parser.Rule, useOffset int64, flip bool, fullMsg *strings.Builder, lastMime *string, depth int) bool {
	name, ok := r.Value.(string)
	if !ok {
		return false
	}
	name = strings.TrimPrefix(name, `\`)
	if strings.HasPrefix(name, "^") {
		flip = !flip
		name = name[1:]
	}
	subRule, found := m.namedRules[name]
	if !found {
		return false
	}
	// Print into the caller buffer so a "\b" continuation can sit against
	// the text already there. Roll back when the subroutine misses.
	saved := fullMsg.String()
	savedMime := *lastMime
	if subRule.Message != "" {
		appendMagicText(fullMsg, parser.FormatMessage(subRule.Message, subRule.Type, nil))
	}
	if !m.walk(data, subRule.Children, useOffset, useOffset, true, flip, fullMsg, lastMime, depth) {
		fullMsg.Reset()
		fullMsg.WriteString(saved)
		*lastMime = savedMime
		return false
	}
	return true
}

func appendMagicText(fullMsg *strings.Builder, msg string) {
	if msg == "" {
		return
	}
	if strings.HasPrefix(msg, "\\b") {
		fullMsg.WriteString(msg[2:])
		return
	}
	if fullMsg.Len() > 0 && !strings.HasSuffix(fullMsg.String(), " ") {
		fullMsg.WriteString(" ")
	}
	fullMsg.WriteString(msg)
}

func swapEndianType(t string) string {
	switch t {
	case "leshort":
		return "beshort"
	case "beshort":
		return "leshort"
	case "uleshort":
		return "ubeshort"
	case "ubeshort":
		return "uleshort"
	case "lelong":
		return "belong"
	case "belong":
		return "lelong"
	case "ulelong":
		return "ubelong"
	case "ubelong":
		return "ulelong"
	case "lequad":
		return "bequad"
	case "bequad":
		return "lequad"
	case "ulequad":
		return "ubequad"
	case "ubequad":
		return "ulequad"
	case "lestring16":
		return "bestring16"
	case "bestring16":
		return "lestring16"
	case "l":
		return "L"
	case "L":
		return "l"
	case "s":
		return "S"
	case "S":
		return "s"
	default:
		return t
	}
}

// MatchPath recursively walks the rule tree.
// It returns the slice of all matching rules from the root to the leaf.
// Note: This only returns the FIRST matching path, which is useful for debugging/tests.
func MatchPath(data []byte, rules []parser.Rule, baseOffset int64) []*parser.Rule {
	for i := range rules {
		if matched, matchedOffset := rules[i].Match(data, baseOffset, false); matched {
			childPath := MatchPath(data, rules[i].Children, matchedOffset)
			return append([]*parser.Rule{&rules[i]}, childPath...)
		}
	}
	return nil
}
