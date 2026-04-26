package parser

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

type Parser struct {
	logger *slog.Logger
}

func NewParser(logger *slog.Logger) *Parser {
	if logger == nil {
		logger = slog.Default()
	}
	return &Parser{logger: logger}
}

func (p *Parser) Parse(r io.Reader) ([]Rule, error) {
	tempRules := []Rule{}

	scanner := bufio.NewScanner(r)

	// This map keeps track of the last rule added at each level.
	// levelParents[0] = the most recent Level 0 rule
	// levelParents[1] = the most recent Level 1 rule
	levelParents := make(map[int]*Rule)

	var lastAddedRule *Rule

	lineNum := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineNum++

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle magic attributes
		if strings.HasPrefix(line, "!:") {
			if strings.HasPrefix(line, "!:mime") {
				if lastAddedRule != nil {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						lastAddedRule.Mime = parts[1]
					}
				}
			}
			// For now, we skip other attributes (!:apple, !:ext, etc.)
			continue
		}

		rule, err := ParseLine(line)
		if err != nil {
			// CRITICAL: Wrap the error with the line number and content
			return nil, fmt.Errorf("line %d: %w (content: %q)", lineNum, err, line)
		}
		if rule == nil {
			continue
		}

		if rule.Level == 0 {
			// Top-level rule: add to RootRules
			tempRules = append(tempRules, *rule)
			levelParents[0] = &tempRules[len(tempRules)-1]
		} else {
			// Sub-rule: Find the parent at Level - 1
			parent, ok := levelParents[rule.Level-1]
			if ok {
				parent.Children = append(parent.Children, *rule)
				// Update the stack so children of THIS rule can find their parent
				levelParents[rule.Level] = &parent.Children[len(parent.Children)-1]
			}
		}

		lastAddedRule = levelParents[rule.Level]
	}
	// fmt.Println("Finished parsing with", len(p.Rules), "root rules.")
	return tempRules, scanner.Err()
}
