package libmagix

import "github.com/wesleylin/libmagix/internal/parser"

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
