package parser

// Strength is the weight file uses to order level-0 tests.
// A longer exact string outranks a short one. "!:strength /2" halves it.
// A rule with an empty description gets one extra point.
func (r *Rule) Strength() int {
	if r.Type == "default" {
		return finishStrength(0, r)
	}
	val := 20
	switch r.Type {
	case "string", "pstring", "octal":
		val += 10 * valueLen(r)
	case "bestring16", "lestring16":
		n := valueLen(r)
		val += 10 * n / 2
	case "search":
		n := valueLen(r)
		if n > 0 {
			per := 10 / n
			if per < 1 {
				per = 1
			}
			val += n * per
		}
	case "regex":
		v := nonmagic(valueString(r))
		per := 10 / v
		if per < 1 {
			per = 1
		}
		val += v * per
	case "indirect", "name", "use", "clear":
	default:
		if ts := typeSize(r.Type); ts > 0 {
			val += ts * 10
		}
	}
	switch r.Operator {
	case "x", "!":
		val = 0
	case "", "=":
		val += 10
	case ">", "<":
		val -= 20
	case "^", "&":
		val -= 10
	}
	return finishStrength(val, r)
}

func finishStrength(val int, r *Rule) int {
	switch r.StrengthOp {
	case "+":
		val += int(r.StrengthArg)
	case "-":
		val -= int(r.StrengthArg)
	case "*":
		val *= int(r.StrengthArg)
	case "/":
		if r.StrengthArg != 0 {
			val /= int(r.StrengthArg)
		}
	}
	if val <= 0 {
		val = 1
	}
	if r.Message == "" {
		val++
	}
	return val
}

func valueString(r *Rule) string {
	s, _ := r.Value.(string)
	return s
}

func valueLen(r *Rule) int {
	return len(valueString(r))
}

// nonmagic counts the literal bytes in a regex. Metacharacters add nothing,
// and a bracket expression adds nothing until its closing bracket.
func nonmagic(s string) int {
	rv := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				i++
			}
			rv++
		case '?', '*', '.', '+', '^', '$':
		case '[':
			for i+1 < len(s) && s[i+1] != ']' {
				i++
			}
		case '{':
			for i+1 < len(s) && s[i+1] != '}' {
				i++
			}
			if i+1 < len(s) {
				i++
			}
		default:
			rv++
		}
	}
	if rv == 0 {
		return 1
	}
	return rv
}

func typeSize(t string) int {
	switch t {
	case "byte", "ubyte":
		return 1
	case "short", "beshort", "leshort", "ubeshort", "uleshort", "uint16",
		"msdosdate", "lemsdosdate", "bemsdosdate",
		"msdostime", "lemsdostime", "bemsdostime":
		return 2
	case "long", "belong", "lelong", "melong", "ubelong", "ulelong", "uint32",
		"date", "ldate", "bedate", "ledate", "medate", "beldate", "leldate", "meldate",
		"float", "befloat", "lefloat":
		return 4
	case "quad", "bequad", "lequad", "ubequad", "ulequad",
		"qdate", "lqdate", "beqdate", "beqldate", "leqdate", "leqldate",
		"double", "bedouble", "ledouble", "offset":
		return 8
	case "guid", "beguid", "leguid":
		return 16
	default:
		return 0
	}
}
