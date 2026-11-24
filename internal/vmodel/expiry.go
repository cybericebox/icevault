package vmodel

import (
	"fmt"
	"sort"
	"time"

	"github.com/cybericebox/icevault/pkg/vault"
)

// An expiry is a date (YYYY-MM-DD, valid through that day) on a secret value that has a lifetime: a variable, a shared variable, an other secret or
// a field of a connection. A variable and an other secret keep it as the native expiry of their KeePass entry, so KeePassXC shows it. A connection is
// one entry with many fields: each field's date is the custom field IceVault.Expires.<field>, and the expiry of the entry is the earliest of them.

// DayFormat is the form of an expiry date.
const DayFormat = "2006-01-02"

// SoonDays is how many days ahead a date counts as "expiring soon".
const SoonDays = 14

const fExpiresPrefix = "IceVault.Expires."

// ParseDay reads an expiry date ("" = never: the zero time).
func ParseDay(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(DayFormat, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not a date (YYYY-MM-DD)", s)
	}
	return t, nil
}

// Today is the day of t in UTC (the day an expiry date is compared with).
func Today(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func dayText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(DayFormat)
}

// ExpiryState says where a date stands on a day: "" (no date, or far ahead), "expired" (the date is before today) or "soon" (today to days ahead).
func ExpiryState(date string, today time.Time, days int) string {
	d, err := ParseDay(date)
	if err != nil || d.IsZero() {
		return ""
	}
	today = Today(today)
	switch {
	case d.Before(today):
		return "expired"
	case !d.After(today.AddDate(0, 0, days)):
		return "soon"
	}
	return ""
}

// ExpiryPlace says where an expiring value lives: Scope is shared, connection (Name = the connection), environment, site or product (Env and Name), or other.
type ExpiryPlace struct{ Scope, Env, Name string }

// String is the place as the command line says it ("environment prod site main").
func (p ExpiryPlace) String() string {
	switch p.Scope {
	case "connection":
		return "connection " + p.Name
	case "environment":
		return "environment " + p.Env
	case "site", BatchProduct:
		return "environment " + p.Env + " " + p.Scope + " " + p.Name
	}
	return p.Scope
}

// ExpiryItem is one value that has an expiry: where it lives and its name (never its value).
type ExpiryItem struct {
	Place ExpiryPlace
	Name  string
	Date  string
	State string // expired | soon
}

type itemSet struct {
	today time.Time
	days  int
	seen  map[string]bool
	out   []ExpiryItem
}

func (s *itemSet) add(where ExpiryPlace, name, date string) {
	st := ExpiryState(date, s.today, s.days)
	key := where.String() + "\x00" + name
	if st == "" || s.seen[key] {
		return
	}
	s.seen[key] = true
	s.out = append(s.out, ExpiryItem{Place: where, Name: name, Date: date, State: st})
}

func (s *itemSet) vars(where ExpiryPlace, vs []*Var) {
	for _, x := range vs {
		s.add(where, x.Key, x.Expires)
	}
}

func (s *itemSet) conn(c *Connection) {
	if c == nil {
		return
	}
	for _, f := range c.Fields {
		s.add(ExpiryPlace{Scope: "connection", Name: c.Name}, f.Name, f.Expires)
	}
}

func (s *itemSet) sorted() []ExpiryItem {
	sort.SliceStable(s.out, func(i, j int) bool {
		a, b := s.out[i], s.out[j]
		if a.Date != b.Date {
			return a.Date < b.Date
		}
		if a.Place != b.Place {
			return a.Place.String() < b.Place.String()
		}
		return a.Name < b.Name
	})
	return s.out
}

// Expiring lists every value of the vault that has expired or expires within days, the earliest first.
func (m *Vault) Expiring(today time.Time, days int) []ExpiryItem {
	s := &itemSet{today: today, days: days, seen: map[string]bool{}}
	s.vars(ExpiryPlace{Scope: "shared"}, m.Shared)
	for _, c := range m.Connections {
		s.conn(c)
	}
	for _, e := range m.Envs {
		s.vars(ExpiryPlace{Scope: "environment", Env: e.Name}, e.General)
		for _, st := range e.Sites {
			s.vars(ExpiryPlace{Scope: "site", Env: e.Name, Name: st.Name}, st.Vars)
		}
		for _, p := range e.Products {
			s.vars(ExpiryPlace{Scope: BatchProduct, Env: e.Name, Name: p.Name}, p.Vars)
			for _, k := range sortedKeys(p.Sub) {
				s.vars(ExpiryPlace{Scope: BatchProduct, Env: e.Name, Name: p.Name}, p.Sub[k])
			}
		}
	}
	for _, o := range m.Other {
		s.add(ExpiryPlace{Scope: "other"}, o.Title, o.Expires)
	}
	return s.sorted()
}

// ExpiringIn lists what an export or a session of one environment uses that has expired or expires within days: its own variables, the shared ones it
// imports, the connections of its sites and enabled products.
func (m *Vault) ExpiringIn(e *Environment, today time.Time, days int) []ExpiryItem {
	s := &itemSet{today: today, days: days, seen: map[string]bool{}}
	s.vars(ExpiryPlace{Scope: "environment", Env: e.Name}, e.General)
	for _, x := range e.Imports {
		s.add(ExpiryPlace{Scope: "shared"}, x.Key, x.Expires)
	}
	for _, st := range e.Sites {
		s.vars(ExpiryPlace{Scope: "site", Env: e.Name, Name: st.Name}, st.Vars)
		s.conn(st.Connection)
		s.conn(st.State)
	}
	for _, p := range e.Products {
		if !p.Enabled {
			continue
		}
		s.vars(ExpiryPlace{Scope: BatchProduct, Env: e.Name, Name: p.Name}, p.Vars)
		for _, k := range sortedKeys(p.Sub) {
			s.vars(ExpiryPlace{Scope: BatchProduct, Env: e.Name, Name: p.Name}, p.Sub[k])
		}
		for _, c := range p.Connections {
			s.conn(c)
		}
	}
	return s.sorted()
}

// connExpiry is the earliest date of the fields of a connection ("" when none has one).
func connExpiry(c *Connection) string {
	min := ""
	for _, f := range c.Fields {
		if f.Expires != "" && (min == "" || f.Expires < min) {
			min = f.Expires
		}
	}
	return min
}

// dayOf is the date of an entry's expiry as the model keeps it.
func dayOf(i vault.EntryInfo) string { return dayText(i.Expires) }
