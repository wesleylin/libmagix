package parser

import (
	"bufio"
	"io"
	"strings"
)

type Parser struct {
	Rules []Rule
}

func NewParser() *Parser {
	return &Parser{Rules: []Rule{}}
}

func (p *Parser) Parse(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	var lastRule *Rule

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 1. Skip empty/comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 2. Handle the MIME attribute
		if strings.HasPrefix(line, "!:mime") {
			if lastRule != nil {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					// Directly update the Mime field of the last rule we added
					lastRule.Mime = parts[1]
				}
			}
			continue
		}

		// 3. Handle standard rules using your ParseLine
		rule, err := ParseLine(line)
		if err != nil {
			continue // In a real app, maybe log the error
		}
		if rule == nil {
			continue
		}

		// Add to our slice and keep a pointer to it for potential MIME updates
		p.Rules = append(p.Rules, *rule)
		lastRule = &p.Rules[len(p.Rules)-1]
	}

	return scanner.Err()
}
