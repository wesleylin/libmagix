package libmagix

import (
	"log/slog"
	"os"
	"strings"

	"github.com/wesleylin/libmagix/internal/parser"
)

type Magix struct {
	rules  []parser.Rule
	logger *slog.Logger
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

	var rules []parser.Rule
	if info.IsDir() {
		rules, err = p.LoadDirectory(magicPath)
	} else {
		rules, err = p.LoadFile(magicPath)
	}

	if err != nil {
		return nil, err
	}
	logger.Debug("Loaded", slog.Int("rules", len(rules)), slog.String("root rules from", magicPath))
	return &Magix{rules: rules, logger: logger}, nil
}

// Identify takes file bytes and returns a Result containing the full, concatenated description.
func (m *Magix) Identify(data []byte) *Result {
	for i := range m.rules {
		if matched, matchedOffset := m.rules[i].Match(data, 0); matched {
			var fullMsg strings.Builder
			var lastMime string

			m.identifyRecursive(data, &m.rules[i], matchedOffset, &fullMsg, &lastMime)

			return &Result{
				Message: fullMsg.String(),
				Mime:    lastMime,
			}
		}
	}
	return nil
}

func (m *Magix) identifyRecursive(data []byte, r *parser.Rule, lastMatchOffset int64, fullMsg *strings.Builder, lastMime *string) {
	msg := r.Message
	if r.Mime != "" {
		*lastMime = r.Mime
	}

	if msg != "" {
		// Handle backspace \b
		if strings.HasPrefix(msg, "\\b") {
			fullMsg.WriteString(msg[2:])
		} else {
			if fullMsg.Len() > 0 {
				fullMsg.WriteString(" ")
			}
			fullMsg.WriteString(msg)
		}
	}

	// Try all children. In libmagic, multiple children at the same level can match.
	for i := range r.Children {
		// Relative rules (&) use the lastMatchOffset
		if matched, matchedOffset := r.Children[i].Match(data, lastMatchOffset); matched {
			m.identifyRecursive(data, &r.Children[i], matchedOffset, fullMsg, lastMime)
		}
	}
}

// MatchPath recursively walks the rule tree.
// It returns the slice of all matching rules from the root to the leaf.
// Note: This only returns the FIRST matching path, which is useful for debugging/tests.
func MatchPath(data []byte, rules []parser.Rule, baseOffset int64) []*parser.Rule {
	for i := range rules {
		if matched, matchedOffset := rules[i].Match(data, baseOffset); matched {
			childPath := MatchPath(data, rules[i].Children, matchedOffset)
			return append([]*parser.Rule{&rules[i]}, childPath...)
		}
	}
	return nil
}
