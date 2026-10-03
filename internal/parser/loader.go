package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (p *Parser) LoadFile(path string) ([]Rule, error) {
	p.logger.Debug("loading single magic file", "path", path)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return p.Parse(f)
}

// LoadDirectory scans a folder and parses all magic files found inside.
// The vendored tree at magic/upstream/Magdir is gated by magic/allowlist:
// only listed basenames are opened. Other directories are loaded in full.
func (p *Parser) LoadDirectory(dirPath string) ([]Rule, error) {
	var allRootRules []Rule

	allow, gated, err := allowlistFor(dirPath)
	if err != nil {
		return nil, err
	}

	// Walk the directory
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and hidden files (like .DS_Store)
		if info.IsDir() || info.Name()[0] == '.' {
			return nil
		}

		if gated {
			if _, ok := allow[info.Name()]; !ok {
				p.logger.Debug("skipping magic file not on allowlist", "path", path)
				return nil
			}
		}

		p.logger.Debug("loading magic file", "path", path)
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		tempRules, err := p.Parse(f)
		if err != nil {
			if gated {
				return fmt.Errorf("parsing %s: %w", path, err)
			}
			// You might want to log the error and continue
			// rather than stopping the whole app for one bad file
			p.logger.Warn("skipping magic file", "path", path, "err", err)
			return nil
		}

		// Add these root rules to our master list
		allRootRules = append(allRootRules, tempRules...)

		// Add these root rules to our master list
		p.logger.Debug("existing rules:" + fmt.Sprint(len(allRootRules)))
		return nil
	})

	return allRootRules, err
}

// allowlistFor returns the basename set that gates dirPath.
// It applies only to magic/upstream/Magdir, whose list is magic/allowlist.
// gated is false when that file is absent, and every magic file is loaded.
func allowlistFor(dirPath string) (map[string]struct{}, bool, error) {
	if filepath.Base(filepath.Dir(dirPath)) != "upstream" {
		return nil, false, nil
	}
	path := filepath.Join(dirPath, "..", "..", "allowlist")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer f.Close()

	allow := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		allow[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, false, err
	}
	return allow, true, nil
}
