package libmagix

import (
	"fmt"

	"github.com/wesleylin/libmagix/internal/parser"
)

type Magix struct {
	rules []parser.Rule
}

// New loads all magic files from the specified directory.
func New(magicDir string) (*Magix, error) {
	rules, err := parser.LoadDirectory(magicDir)
	if err != nil {
		return nil, err
	}
	fmt.Println("Loaded", len(rules), "root rules from", magicDir)
	fmt.Println("Sample rule:", rules[0])
	return &Magix{rules: rules}, nil
}

// Identify takes file bytes and returns the match.
func (m *Magix) Identify(data []byte) *parser.Rule {
	return MatchTree(data, m.rules)
}

// MatchTree recursively walks the rule tree.
// It returns the most specific (deepest) match found.
func MatchTree(data []byte, rules []parser.Rule) *parser.Rule {

	for i := range rules {
		if rules[i].Match(data) {
			// if any children match, prefer them.
			// Children are more specific (e.g., "Zip" -> "DocX").
			childMatch := MatchTree(data, rules[i].Children)
			if childMatch != nil {
				return childMatch
			}

			// If no children match, this parent is the best we've got.
			return &rules[i]
		}
	}

	return nil
}
