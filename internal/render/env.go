// Package render lays the resolved namespace of an environment out as the
// settings files the project's scripts read, byte for byte, and applies the
// rules of the project description: the templates (the sample files), the file
// rules, the visibility rules, where an import puts a variable, the checklist.
package render

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/cybericebox/icevault/internal/model"
)

var keyLineRE = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
var tailCommentRE = regexp.MustCompile(`\s+#`)
var quoteNeededRE = regexp.MustCompile("[\\s#'\"<>$`\\\\&|;()]")

// ParseValue: "..." or '...' up to the closing quote, else up to whitespace
// followed by #. Returns the value and the tail (the rest of the line).
func ParseValue(raw string) (value, tail string) {
	raw = strings.TrimSpace(raw)
	if raw != "" && (raw[0] == '"' || raw[0] == '\'') {
		q := raw[0]
		if end := strings.IndexByte(raw[1:], q); end >= 0 {
			end++ // index in raw
			return raw[1:end], raw[end+1:]
		}
	}
	if strings.HasPrefix(raw, "#") {
		return "", " " + raw
	}
	if loc := tailCommentRE.FindStringIndex(raw); loc != nil {
		return strings.TrimSpace(raw[:loc[0]]), raw[loc[0]:]
	}
	return raw, ""
}

// QuoteEnv is the quoting rule of a settings file, made safe for `source` in bash, docker compose, node --env-file and the project's own reader:
// a value is written as it is when it needs no quote, in double quotes when nothing in it is special inside them, else in single quotes (nothing is special
// there). Inside double quotes bash and compose expand $, a backtick runs a command in bash, and a backslash before a quote swallows the rest of the file, so
// a value with one of them must not get double quotes (`$(cmd)` in a value would run when an env file is sourced). A leading ~ (or one after
// : or =) is a tilde expansion in bash and is quoted too. A value with both kinds of quote and a special character has no form that every reader gives back;
// it is written in the bash form 'a'\”b' (safe for source, never executed) (the model refuses line breaks in values, so no value needs a form that spans lines).
func QuoteEnv(v string) string {
	if v != "" && !quoteNeededRE.MatchString(v) && !tildeRE.MatchString(v) {
		return v
	}
	special := strings.ContainsAny(v, "$`\\")
	if !strings.Contains(v, "\"") && !special {
		return `"` + v + `"`
	}
	if !strings.Contains(v, "'") {
		return "'" + v + "'"
	}
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

var tildeRE = regexp.MustCompile(`(^|[:=])~`)

var styleOrder = []string{"a", "p", "d", "s"}

func quoteStyle(style, v string) string {
	switch style {
	case "a":
		return QuoteEnv(v)
	case "p":
		return v
	case "d":
		return `"` + v + `"`
	default:
		return "'" + v + "'"
	}
}

// LayoutLine is one line of a stored layout: a literal text, or a variable
// line without its value (indent, key, lead, tail, quoting style).
type LayoutLine struct {
	Lit   string // when IsLit
	IsLit bool
	K, I  string
	L, T  string
	S     string // a (auto), p (plain), d ("), s ('), r (raw: keep Line while the value is Raw's)
	Raw   string
	Line  string
}

// Layout is a settings file WITHOUT its values: comments, order, quoting style.
type Layout struct {
	V     int
	Lines []LayoutLine
}

// EmptyLayout is the layout of a file that is not stored.
func EmptyLayout() Layout { return Layout{V: 1} }

// RenderItem is one variable line with the value.
func RenderItem(it LayoutLine, value string) string {
	var token string
	if it.S == "r" {
		orig, _ := ParseValue(it.Raw)
		if value == orig {
			return it.Line
		}
		token = QuoteEnv(value)
	} else {
		token = quoteStyle(it.S, value)
	}
	return it.I + it.K + "=" + it.L + token + it.T
}

// Var is a variable of a parsed file: name, value, the comments that describe it.
type Var struct{ Name, Value, Notes string }

// ParseEnv parses a settings file into its layout and variables (in file
// order). The first of a repeated key stays a literal line (the last wins).
func ParseEnv(text string) (Layout, []Var) {
	type slot struct {
		line LayoutLine
		v    string
		n    string
		isV  bool
	}
	var parsed []slot
	var pending []string
	last := map[string][2]any{} // key -> (index, literal line)
	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		switch {
		case s == "":
			parsed = append(parsed, slot{line: LayoutLine{Lit: line, IsLit: true}})
			pending = nil
		case strings.HasPrefix(s, "#"):
			parsed = append(parsed, slot{line: LayoutLine{Lit: line, IsLit: true}})
			pending = append(pending, s)
		default:
			m := keyLineRE.FindStringSubmatch(s)
			if m == nil {
				parsed = append(parsed, slot{line: LayoutLine{Lit: line, IsLit: true}})
				pending = nil
				continue
			}
			raw := m[2]
			value, tail := ParseValue(raw)
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t\v\f\r"))]
			lead := raw[:len(raw)-len(strings.TrimLeft(raw, " \t\v\f\r"))]
			item := LayoutLine{K: m[1], I: indent, L: lead, T: tail}
			found := false
			for _, st := range styleOrder {
				item.S = st
				if RenderItem(item, value) == line {
					found = true
					break
				}
			}
			if !found {
				item.S, item.Raw, item.Line = "r", raw, line
			}
			var cs []string
			for _, c := range pending {
				cs = append(cs, strings.TrimSpace(strings.TrimLeft(c, "#")))
			}
			notes := strings.Join(cs, "\n")
			if strings.HasPrefix(strings.TrimSpace(tail), "#") {
				if notes != "" {
					notes += "\n"
				}
				notes += strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(tail), "#"))
			}
			if prev, ok := last[m[1]]; ok {
				parsed[prev[0].(int)] = slot{line: LayoutLine{Lit: prev[1].(string), IsLit: true}}
			}
			lit := RenderItem(item, value)
			if item.S == "r" {
				lit = item.Line
			}
			last[m[1]] = [2]any{len(parsed), lit}
			parsed = append(parsed, slot{line: item, v: value, n: notes, isV: true})
			pending = nil
		}
	}
	lay := Layout{V: 1}
	var vars []Var
	for _, p := range parsed {
		lay.Lines = append(lay.Lines, p.line)
		if p.isV {
			vars = append(vars, Var{p.line.K, p.v, p.n})
		}
	}
	return lay, vars
}

// Vars is an ordered name -> value map (the order is the order of the entries).
type Vars struct {
	Order []string
	M     map[string]string
}

func NewVars() *Vars { return &Vars{M: map[string]string{}} }

// Set stores a value, keeping the first position of a name.
func (v *Vars) Set(name, value string) {
	if _, ok := v.M[name]; !ok {
		v.Order = append(v.Order, name)
	}
	v.M[name] = value
}
func (v *Vars) Get(name string) (string, bool) { s, ok := v.M[name]; return s, ok }
func (v *Vars) Len() int                       { return len(v.Order) }

// VarsOf builds Vars from parsed variables.
func VarsOf(vs []Var) *Vars {
	out := NewVars()
	for _, x := range vs {
		out.Set(x.Name, x.Value)
	}
	return out
}

// RenderEnv is the file text: the layout with each variable's value; a
// variable without a value is left out, one that is not in the layout is
// appended at the end.
func RenderEnv(l Layout, values *Vars) string {
	var out []string
	used := map[string]bool{}
	for _, it := range l.Lines {
		if it.IsLit {
			out = append(out, it.Lit)
		} else if val, ok := values.Get(it.K); ok {
			used[it.K] = true
			out = append(out, RenderItem(it, val))
		}
	}
	var extra []string
	for _, k := range values.Order {
		if !used[k] {
			extra = append(extra, k+"="+QuoteEnv(values.M[k]))
		}
	}
	if len(extra) > 0 {
		for len(out) > 0 && out[len(out)-1] == "" {
			out = out[:len(out)-1]
		}
		if len(out) > 0 {
			out = append(out, "")
		}
		out = append(out, "# ---- added in the vault ----")
		out = append(out, extra...)
		out = append(out, "")
	}
	return strings.Join(out, "\n")
}

// ParseEnvChecked is ParseEnv plus the proof that layout and values give the
// file back byte for byte (else an import would change the file).
func ParseEnvChecked(rel, text string) (Layout, []Var, error) {
	l, vs := ParseEnv(text)
	if err := CheckSingleLine(rel, vs); err != nil {
		return l, vs, err
	}
	if RenderEnv(l, VarsOf(vs)) != text {
		return l, vs, &model.StoreError{Msg: rel + ": cannot be kept byte for byte (an unusual line); simplify the file and import again"}
	}
	return l, vs, nil
}

// CheckSingleLine refuses a value with a line break (never shows it).
func CheckSingleLine(rel string, vs []Var) error {
	for _, v := range vs {
		if strings.ContainsAny(v.Value, "\n\r") {
			return &model.StoreError{Msg: fmt.Sprintf("%s: the value of %s has a line break, which the vault entries cannot carry", rel, v.Name)}
		}
	}
	return nil
}

// ---- the layout as the vault stores it: JSON, keys sorted

// CanonJSON is the canonical JSON of a layout: keys sorted, the separators ", " and ": ".
func CanonJSON(l Layout) string {
	var b strings.Builder
	b.WriteString(`{"lines": [`)
	for i, it := range l.Lines {
		if i > 0 {
			b.WriteString(", ")
		}
		if it.IsLit {
			b.WriteString(pyString(it.Lit))
			continue
		}
		fields := [][2]string{{"i", it.I}, {"k", it.K}, {"l", it.L}}
		if it.S == "r" {
			fields = append(fields, [2]string{"line", it.Line}, [2]string{"raw", it.Raw})
		}
		fields = append(fields, [2]string{"s", it.S}, [2]string{"t", it.T})
		b.WriteString("{")
		for j, f := range fields {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString(pyString(f[0]) + ": " + pyString(f[1]))
		}
		b.WriteString("}")
	}
	fmt.Fprintf(&b, `], "v": %d}`, l.V)
	return b.String()
}

// pyString is a JSON string as Python's json.dumps writes it (ensure_ascii).
func pyString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20:
			fmt.Fprintf(&b, `\u%04x`, r)
		case r < 0x80:
			b.WriteRune(r)
		case r == utf8.RuneError:
			b.WriteString(`\ufffd`)
		case r >= 0x10000:
			r -= 0x10000
			fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ParseLayoutJSON reads a stored layout.
func ParseLayoutJSON(data []byte) (Layout, error) {
	var raw struct {
		V     int               `json:"v"`
		Lines []json.RawMessage `json:"lines"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return Layout{}, err
	}
	l := Layout{V: raw.V}
	for _, m := range raw.Lines {
		var s string
		if json.Unmarshal(m, &s) == nil {
			l.Lines = append(l.Lines, LayoutLine{Lit: s, IsLit: true})
			continue
		}
		var o struct{ K, I, L, T, S, Raw, Line string }
		if err := json.Unmarshal(m, &o); err != nil {
			return Layout{}, err
		}
		if o.K == "" {
			return Layout{}, fmt.Errorf("a layout line without a key")
		}
		l.Lines = append(l.Lines, LayoutLine{K: o.K, I: o.I, L: o.L, T: o.T, S: o.S, Raw: o.Raw, Line: o.Line})
	}
	return l, nil
}
