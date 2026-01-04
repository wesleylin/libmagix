package parser

import (
	"fmt"
	"os"
	"path/filepath"
)

// LoadDirectory scans a folder and parses all magic files found inside.
func (p *Parser) LoadDirectory(dirPath string) ([]Rule, error) {
	var allRootRules []Rule

	// Walk the directory
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and hidden files (like .DS_Store)
		if info.IsDir() || info.Name()[0] == '.' {
			return nil
		}

		// Open the magic file
		fmt.Println("Loading magic file:", path)
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		tempRules, err := p.Parse(f)
		if err != nil {
			// You might want to log the error and continue
			// rather than stopping the whole app for one bad file
			fmt.Printf("Error parsing file %s: %v\n", path, err)
			return nil
		}

		// Add these root rules to our master list
		allRootRules = append(allRootRules, tempRules...)

		// Add these root rules to our master list
		fmt.Println("existing rules:", allRootRules)
		// allRootRules = append(allRootRules, p.Rules...)
		fmt.Println("Total rules so far:", allRootRules)
		return nil
	})

	return allRootRules, err
}
