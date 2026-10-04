package libmagix

import (
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/wesleylin/libmagix/internal/parser"
)

type Magix struct {
	rules       []parser.Rule
	binaryOrder []int
	namedRules  map[string]*parser.Rule
	logger      *slog.Logger
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
	return newFromRules(rawRules, logger, magicPath), nil
}

// NewFiles loads magic from the given files, in order.
// Tests use this for a sample that ships its own magic database.
func NewFiles(paths []string, logger *slog.Logger) (*Magix, error) {
	if logger == nil {
		logger = slog.Default()
	}
	p := parser.NewParser(logger)
	var raw []parser.Rule
	for _, path := range paths {
		rules, err := p.LoadFile(path)
		if err != nil {
			return nil, err
		}
		raw = append(raw, rules...)
	}
	return newFromRules(raw, logger, strings.Join(paths, ",")), nil
}

func newFromRules(rawRules []parser.Rule, logger *slog.Logger, from string) *Magix {
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
	// The binary pass tries the strongest level-0 test first. Equal strengths
	// keep source order, and a level-0 default stays last. The text pass keeps
	// source order so an earlier description such as SVG still wins.
	binaryOrder := make([]int, len(mainRules))
	for i := range binaryOrder {
		binaryOrder[i] = i
	}
	sort.SliceStable(binaryOrder, func(i, j int) bool {
		return mainRules[binaryOrder[i]].Strength() > mainRules[binaryOrder[j]].Strength()
	})
	binaryOrder = defaultsLast(mainRules, binaryOrder)
	logger.Debug("Loaded", slog.Int("rules", len(mainRules)), slog.Int("named_blocks", len(namedRules)), slog.String("from", from))
	return &Magix{rules: mainRules, binaryOrder: binaryOrder, namedRules: namedRules, logger: logger}
}

func defaultsLast(rules []parser.Rule, order []int) []int {
	var rest, defs []int
	for _, i := range order {
		if rules[i].Type == "default" {
			defs = append(defs, i)
			continue
		}
		rest = append(rest, i)
	}
	return append(rest, defs...)
}

type hit struct {
	msg      string
	mime     string
	strength int
	index    int
}

// Identify takes file bytes and returns a Result containing the full, concatenated description.
func (m *Magix) Identify(data []byte) *Result {
	return m.identify(data, false)
}

// IdentifyContinue reports every level-0 hit, the way file -k does.
func (m *Magix) IdentifyContinue(data []byte) *Result {
	return m.identify(data, true)
}

// identify follows file_buffer: JSON, then the binary magic pass.
// A binary hit is the whole answer. Otherwise the text pass runs on
// ASCII or decoded UTF-16 and the encoding phrase is appended.
func (m *Magix) identify(data []byte, cont bool) *Result {
	if msg, ok := jsonMessage(data); ok {
		return &Result{Message: msg}
	}
	view, code, textual := textView(data)
	// A /b string is skipped when the bytes already look like text.
	// The text pass then prints the /t description instead.
	binary := m.collect(data, false, cont, textual)
	if len(binary) > 0 && !cont {
		return &Result{Message: binary[0].msg, Mime: binary[0].mime}
	}
	var hits []hit
	hits = append(hits, binary...)
	if textual {
		hits = append(hits, m.collect(view, true, cont, false)...)
	}
	if len(hits) == 0 {
		if !textual {
			return nil
		}
		return &Result{Message: escapeControls(appendTextTail("", code, view))}
	}
	if cont && len(hits) > 1 {
		sort.SliceStable(hits, func(i, j int) bool {
			if hits[i].strength != hits[j].strength {
				return hits[i].strength > hits[j].strength
			}
			return hits[i].index > hits[j].index
		})
	}
	msg, mime := joinHits(hits)
	if textual && len(binary) == 0 {
		msg = appendTextTail(msg, code, view)
	}
	return &Result{Message: escapeControls(msg), Mime: mime}
}

func (m *Magix) collect(data []byte, textPass, cont, looksText bool) []hit {
	var hits []hit
	order := m.binaryOrder
	if textPass {
		order = make([]int, len(m.rules))
		for i := range order {
			order[i] = i
		}
	}
	for _, i := range order {
		r := &m.rules[i]
		if !r.MatchesPass(textPass) {
			continue
		}
		if !textPass && looksText && r.StringFlags&parser.StringBinary != 0 && r.StringFlags&parser.StringText == 0 {
			continue
		}
		matched, matchedOffset, val := r.MatchValue(data, 0, false)
		if !matched {
			continue
		}
		var fullMsg strings.Builder
		var lastMime string
		m.identifyRecursive(data, r, 0, matchedOffset, false, val, false, &fullMsg, &lastMime, 0)
		// A level-0 test with an empty description does not count as a hit
		// unless a continuation printed something. libmagic keeps scanning.
		msg := strings.TrimSpace(fullMsg.String())
		if msg == "" && lastMime == "" {
			continue
		}
		hits = append(hits, hit{
			msg:      msg,
			mime:     lastMime,
			strength: ruleStrength(r),
			index:    i,
		})
		if !cont {
			return hits
		}
	}
	return hits
}

func ruleStrength(r *parser.Rule) int {
	if s, ok := r.Value.(string); ok {
		return len(s)
	}
	return 1
}

func joinHits(hits []hit) (string, string) {
	var b strings.Builder
	var mime string
	for i, h := range hits {
		if i > 0 {
			b.WriteString("\n- ")
		}
		b.WriteString(h.msg)
		if h.mime != "" {
			mime = h.mime
		}
	}
	return b.String(), mime
}

func (m *Magix) identifyRecursive(data []byte, r *parser.Rule, plainBase, relativeBase int64, inUse bool, val any, flip bool, fullMsg *strings.Builder, lastMime *string, depth int) {
	if r.Type == "indirect" {
		appendMagicText(fullMsg, parser.FormatMessage(r.Message, r.Type, val))
		if depth < 2 {
			m.identifyAt(data, relativeBase, fullMsg, lastMime, depth+1)
		}
		m.walk(data, r.Children, plainBase, relativeBase, inUse, flip, fullMsg, lastMime, depth)
		return
	}
	if r.Type == "use" {
		// Continuations of the use line run only after the named block
		// matches. Their relative base is the offset where the use was entered.
		if m.execUse(data, r, relativeBase, flip, fullMsg, lastMime, depth) {
			m.walk(data, r.Children, plainBase, relativeBase, inUse, flip, fullMsg, lastMime, depth)
		}
		return
	}

	if r.Mime != "" {
		*lastMime = r.Mime
	}
	appendMagicText(fullMsg, parser.FormatMessage(r.Message, r.Type, val))

	m.walk(data, r.Children, plainBase, relativeBase, inUse, flip, fullMsg, lastMime, depth)
}

// walk scans rules that share a continuation level.
// default matches only when nothing else at this level has matched.
// clear resets that flag so a later default can still run.
// Inside a subroutine, direct offsets stay relative to plainBase (the use).
// '&' offsets stay relative to relativeBase (the end of the previous match).
func (m *Magix) walk(data []byte, rules []parser.Rule, plainBase, relativeBase int64, inUse, flip bool, fullMsg *strings.Builder, lastMime *string, depth int) bool {
	gotMatch := false
	matchedAny := false
	for i := range rules {
		r := rules[i]
		if r.Type == "default" && gotMatch {
			continue
		}
		if flip {
			r.Type = swapEndianType(r.Type)
			r.PointerType = swapEndianType(r.PointerType)
		}

		base := int64(0)
		forced := false
		if r.IsRelative {
			base = relativeBase
			forced = true
		} else if inUse {
			base = plainBase
			forced = true
		}
		matched, off, val := r.MatchValue(data, base, forced)
		if !matched {
			continue
		}
		if r.Type == "clear" {
			m.identifyRecursive(data, &r, plainBase, off, inUse, val, flip, fullMsg, lastMime, depth)
			gotMatch = false
			continue
		}
		if r.Type == "use" {
			// A use that misses does not block a later default at this level.
			if !m.execUse(data, &r, off, flip, fullMsg, lastMime, depth) {
				continue
			}
			gotMatch = true
			matchedAny = true
			m.walk(data, r.Children, plainBase, off, inUse, flip, fullMsg, lastMime, depth)
			continue
		}
		gotMatch = true
		matchedAny = true
		m.identifyRecursive(data, &r, plainBase, off, inUse, val, flip, fullMsg, lastMime, depth)
	}
	return matchedAny
}

// identifyAt runs the top-level tests as if the file began at base.
// indirect rules use this to describe the bytes they point at.
func (m *Magix) identifyAt(data []byte, base int64, fullMsg *strings.Builder, lastMime *string, depth int) {
	for _, i := range m.binaryOrder {
		matched, off, val := m.rules[i].MatchValue(data, base, true)
		if !matched {
			continue
		}
		var nested strings.Builder
		var mime string
		m.identifyRecursive(data, &m.rules[i], base, off, true, val, false, &nested, &mime, depth)
		if strings.TrimSpace(nested.String()) == "" && mime == "" {
			continue
		}
		text := nested.String()
		if text != "" && fullMsg.Len() > 0 && !strings.HasSuffix(fullMsg.String(), " ") && text[0] != ' ' {
			fullMsg.WriteByte(' ')
		}
		fullMsg.WriteString(text)
		if mime != "" {
			*lastMime = mime
		}
		return
	}
}

func (m *Magix) execUse(data []byte, r *parser.Rule, useOffset int64, flip bool, fullMsg *strings.Builder, lastMime *string, depth int) bool {
	name, ok := r.Value.(string)
	if !ok {
		return false
	}
	name = strings.TrimPrefix(name, `\`)
	if strings.HasPrefix(name, "^") {
		flip = !flip
		name = name[1:]
	}
	subRule, found := m.namedRules[name]
	if !found {
		return false
	}
	// Print into the caller buffer so a "\b" continuation can sit against
	// the text already there. Roll back when the subroutine misses.
	saved := fullMsg.String()
	savedMime := *lastMime
	if subRule.Message != "" {
		appendMagicText(fullMsg, parser.FormatMessage(subRule.Message, subRule.Type, nil))
	}
	if !m.walk(data, subRule.Children, useOffset, useOffset, true, flip, fullMsg, lastMime, depth) {
		fullMsg.Reset()
		fullMsg.WriteString(saved)
		*lastMime = savedMime
		return false
	}
	return true
}

func appendMagicText(fullMsg *strings.Builder, msg string) {
	if msg == "" {
		return
	}
	if strings.HasPrefix(msg, "\\b") {
		fullMsg.WriteString(msg[2:])
		return
	}
	if fullMsg.Len() > 0 && !strings.HasSuffix(fullMsg.String(), " ") {
		fullMsg.WriteString(" ")
	}
	fullMsg.WriteString(msg)
}

func swapEndianType(t string) string {
	switch t {
	case "leshort":
		return "beshort"
	case "beshort":
		return "leshort"
	case "uleshort":
		return "ubeshort"
	case "ubeshort":
		return "uleshort"
	case "lelong":
		return "belong"
	case "belong":
		return "lelong"
	case "ulelong":
		return "ubelong"
	case "ubelong":
		return "ulelong"
	case "lequad":
		return "bequad"
	case "bequad":
		return "lequad"
	case "ulequad":
		return "ubequad"
	case "ubequad":
		return "ulequad"
	case "lestring16":
		return "bestring16"
	case "bestring16":
		return "lestring16"
	case "l":
		return "L"
	case "L":
		return "l"
	case "s":
		return "S"
	case "S":
		return "s"
	default:
		return t
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
