package libmagix

import "github.com/wesleylin/libmagix/internal/parser"

// MatchTree recursively walks the rule tree.
// It returns the most specific (deepest) match found.
func MatchTree(data []byte, rules []parser.Rule) *parser.Rule {
	var bestMatch *parser.Rule

	for _, rule := range rules {
		if rule.Match(data) {
			// If it matches, we assume this is our best match for now...
			bestMatch = &rule

			// ...BUT, we must check if any of its children match.
			// Children are more specific (e.g., "Zip" -> "DocX").
			childMatch := MatchTree(data, rule.Children)
			if childMatch != nil {
				return childMatch
			}

			// If no children match, this parent is the best we've got.
			return bestMatch
		}
	}

	return nil
}
