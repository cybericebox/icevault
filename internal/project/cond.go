package project

import (
	"errors"
	"fmt"
	"strings"
)

// The condition language of a description (variables' when and required-when, files' used-when and partly-used):
//
//	KEY=value            the value of KEY is value (KEY= is empty)
//	KEY!=value           it is not
//	KEY in [a, b]        it is one of the words
//	KEY not in [a, b]    it is none of them
//	KEY has word         a list (words separated by commas or spaces) holds the word
//	not C, C and C, C or C, ( C )
//
// and binds tighter than or. A value may be quoted ("a b"). KEY is a variable of the description, a derived variable, a place variable or a key
// of conditions.defaults; a key the environment does not set has its default, else "".

// Condition is a parsed condition; nil holds always.
type Condition struct {
	op    string // "=", "!=", "in", "not in", "has", "and", "or", "not"
	Key   string
	Value string
	words []string
	sub   []*Condition
}

// Op is the operator of an atom ("=", "!=", "has", "in", "not in") or of a combination ("and", "or", "not").
func (c *Condition) Op() string { return c.op }

type token struct {
	s      string
	quoted bool
}

const opNot = "not"

func tokenize(s string) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch c {
		case ' ', '\t':
			i++
		case '(', ')', '[', ']', ',', '=':
			out = append(out, token{s: string(c)})
			i++
		case '!':
			if i+1 < len(s) && s[i+1] == '=' {
				out = append(out, token{s: "!="})
				i += 2
				continue
			}
			return nil, fmt.Errorf("a lone ! at %d", i)
		case '"', '\'':
			j := strings.IndexByte(s[i+1:], c)
			if j < 0 {
				return nil, errors.New("a quote that is not closed")
			}
			out = append(out, token{s: s[i+1 : i+1+j], quoted: true})
			i += j + 2
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \t()[],=!\"'", rune(s[j])) {
				j++
			}
			out = append(out, token{s: s[i:j]})
			i = j
		}
	}
	return out, nil
}

type parser struct {
	t   []token
	pos int
}

func (p *parser) peek() string {
	if p.pos < len(p.t) && !p.t[p.pos].quoted {
		return p.t[p.pos].s
	}
	if p.pos < len(p.t) {
		return "\x00" + p.t[p.pos].s
	}
	return ""
}

func (p *parser) next() token {
	t := p.t[p.pos]
	p.pos++
	return t
}

func (p *parser) or() (*Condition, error) {
	a, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" {
		p.pos++
		b, err := p.and()
		if err != nil {
			return nil, err
		}
		a = &Condition{op: "or", sub: []*Condition{a, b}}
	}
	return a, nil
}

func (p *parser) and() (*Condition, error) {
	a, err := p.unary()
	if err != nil {
		return nil, err
	}
	for p.peek() == "and" {
		p.pos++
		b, err := p.unary()
		if err != nil {
			return nil, err
		}
		a = &Condition{op: "and", sub: []*Condition{a, b}}
	}
	return a, nil
}

func (p *parser) unary() (*Condition, error) {
	switch p.peek() {
	case opNot:
		p.pos++
		a, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &Condition{op: opNot, sub: []*Condition{a}}, nil
	case "(":
		p.pos++
		a, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, errors.New("a ( without its )")
		}
		p.pos++
		return a, nil
	}
	return p.atom()
}

// value is the value after = or != : a word, a quoted text, or nothing (the end, ), and, or).
func (p *parser) value() string {
	switch p.peek() {
	case "", ")", "and", "or":
		return ""
	}
	return p.next().s
}

func (p *parser) atom() (*Condition, error) {
	if p.pos >= len(p.t) || p.t[p.pos].quoted || !nameRE.MatchString(p.t[p.pos].s) {
		return nil, errors.New(condHelp)
	}
	key := p.next().s
	switch op := p.peek(); op {
	case "=", "!=":
		p.pos++
		return &Condition{op: op, Key: key, Value: p.value()}, nil
	case "has":
		p.pos++
		if p.pos >= len(p.t) {
			return nil, errors.New("has needs a word")
		}
		return &Condition{op: "has", Key: key, Value: p.next().s}, nil
	case "in", opNot:
		p.pos++
		if op == opNot {
			if p.peek() != "in" {
				return nil, errors.New(condHelp)
			}
			p.pos++
			op = "not in"
		}
		if p.peek() != "[" {
			return nil, errors.New("in needs a list: [a, b]")
		}
		p.pos++
		var words []string
		for p.peek() != "]" {
			if p.pos >= len(p.t) {
				return nil, errors.New("a [ without its ]")
			}
			t := p.next()
			if !t.quoted && t.s == "," {
				continue
			}
			words = append(words, t.s)
		}
		p.pos++
		if len(words) == 0 {
			return nil, errors.New("an empty list")
		}
		return &Condition{op: op, Key: key, words: words}, nil
	}
	return nil, errors.New(condHelp)
}

const condHelp = "a condition is KEY=value, KEY!=value, KEY in [a, b], KEY not in [a, b] or KEY has word, combined with and, or, not and ( )"

// ParseWhen parses a condition ("" is none: nil, which holds always).
func ParseWhen(s string) (*Condition, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	t, err := tokenize(s)
	if err != nil {
		return nil, fmt.Errorf("%s (%v)", condHelp, err)
	}
	p := &parser{t: t}
	c, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.t) {
		return nil, fmt.Errorf("%s (%q is left over)", condHelp, p.t[p.pos].s)
	}
	return c, nil
}

// Keys lists the keys the condition reads.
func (c *Condition) Keys() []string {
	if c == nil {
		return nil
	}
	if c.Key != "" {
		return []string{c.Key}
	}
	var out []string
	for _, s := range c.sub {
		out = append(out, s.Keys()...)
	}
	return out
}

// Holds evaluates the condition with the values of the environment (get answers "" for a key that is not set).
func (c *Condition) Holds(get func(string) string) bool {
	if c == nil {
		return true
	}
	switch c.op {
	case "and":
		return c.sub[0].Holds(get) && c.sub[1].Holds(get)
	case "or":
		return c.sub[0].Holds(get) || c.sub[1].Holds(get)
	case opNot:
		return !c.sub[0].Holds(get)
	}
	v := get(c.Key)
	switch c.op {
	case "=":
		return v == c.Value
	case "!=":
		return v != c.Value
	case "in", "not in":
		in := contains(c.words, v)
		return in == (c.op == "in")
	}
	for _, w := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		if w == c.Value {
			return true
		}
	}
	return false
}
