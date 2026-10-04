package parser

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
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
// magic/Magdir is gated by magic/allowlist: only listed basenames are opened.
// Other directories, including magic/fixtures, are loaded in full.
func (p *Parser) LoadDirectory(dirPath string) ([]Rule, error) {
	return p.LoadFS(os.DirFS(filepath.Dir(dirPath)), filepath.Base(dirPath))
}

// LoadFS scans root inside fsys. A directory named Magdir is gated by a
// sibling allowlist file. Other directories are loaded in full.
func (p *Parser) LoadFS(fsys fs.FS, root string) ([]Rule, error) {
	root = path.Clean(root)
	var allRootRules []Rule

	allow, gated, err := allowlistFrom(fsys, root)
	if err != nil {
		return nil, err
	}

	err = fs.WalkDir(fsys, root, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() || name == "" || name[0] == '.' {
			return nil
		}
		if gated {
			if _, ok := allow[name]; !ok {
				p.logger.Debug("skipping magic file not on allowlist", "path", filePath)
				return nil
			}
		}

		p.logger.Debug("loading magic file", "path", filePath)
		f, err := fsys.Open(filePath)
		if err != nil {
			return err
		}
		defer f.Close()

		tempRules, err := p.Parse(f)
		if err != nil {
			if gated {
				return fmt.Errorf("parsing %s: %w", filePath, err)
			}
			p.logger.Warn("skipping magic file", "path", filePath, "err", err)
			return nil
		}
		allRootRules = append(allRootRules, tempRules...)
		p.logger.Debug("existing rules:" + fmt.Sprint(len(allRootRules)))
		return nil
	})
	return allRootRules, err
}

// allowlistFrom returns the basename set that gates root.
// It applies to a directory named Magdir when a sibling allowlist exists.
// gated is false otherwise, and every magic file is loaded.
func allowlistFrom(fsys fs.FS, root string) (map[string]struct{}, bool, error) {
	if path.Base(root) != "Magdir" {
		return nil, false, nil
	}
	f, err := fsys.Open(path.Join(path.Dir(root), "allowlist"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer f.Close()
	return readAllowlist(f)
}

func readAllowlist(r io.Reader) (map[string]struct{}, bool, error) {
	allow := make(map[string]struct{})
	scanner := bufio.NewScanner(r)
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
