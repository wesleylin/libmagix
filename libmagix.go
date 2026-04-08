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
		if matched, matchedOffset := m.rules[i].Match(data, 0, false); matched {
			var fullMsg strings.Builder
			var lastMime string

			m.identifyRecursive(data, &m.rules[i], matchedOffset, &fullMsg, &lastMime)

			return &Result{
				Message: strings.TrimSpace(fullMsg.String()),
				Mime:    lastMime,
			}
		}
	}
	return nil
}

func (m *Magix) identifyRecursive(data []byte, r *parser.Rule, lastMatchOffset int64, fullMsg *strings.Builder, lastMime *string) {
	if r.Type == "use" {
		name, ok := r.Value.(string)
		if ok {
			if subRule, found := m.namedRules[name]; found {
				// Execute all children of the named block using the current lastMatchOffset
				// IMPORTANT: Rules inside a subroutine are forced to be relative to the 'use' offset
				for i := range subRule.Children {
					if matched, matchedOffset := subRule.Children[i].Match(data, lastMatchOffset, true); matched {
						m.identifyRecursive(data, &subRule.Children[i], matchedOffset, fullMsg, lastMime)
					}
				}
			}
		}
		return
	}

	msg := r.Message
	if r.Mime != "" {
		*lastMime = r.Mime
	}

	if msg != "" {
		// Handle backspace \b
		if strings.HasPrefix(msg, "\\b") {
			fullMsg.WriteString(msg[2:])
		} else {
			if fullMsg.Len() > 0 && !strings.HasSuffix(fullMsg.String(), " ") {
				fullMsg.WriteString(" ")
			}
			fullMsg.WriteString(msg)
		}
	}

	// Try all children. In libmagic, multiple children at the same level can match.
	for i := range r.Children {
		// Relative rules (&) use the lastMatchOffset
		if matched, matchedOffset := r.Children[i].Match(data, lastMatchOffset, false); matched {
			m.identifyRecursive(data, &r.Children[i], matchedOffset, fullMsg, lastMime)
		}
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
