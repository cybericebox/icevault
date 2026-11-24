package vault

import (
	"time"

	"github.com/tobischo/gokeepasslib/v3"
)

// The expiry of an entry is the native KeePass one (the "Expires" tick and the expiry time of the entry), so KeePassXC shows it and marks the entry
// when it has passed. A date is kept as the last second of that day (UTC): the entry is valid through its date.

// ExpiryEnd is the instant an expiry date stands for: the last second of that day in UTC.
func ExpiryEnd(day time.Time) time.Time {
	y, m, d := day.Date()
	return time.Date(y, m, d, 23, 59, 59, 0, time.UTC)
}

// Expiry returns the expiry time of an entry; ok is false when the entry does not expire.
func (v *Vault) Expiry(path string) (t time.Time, ok bool, err error) {
	g, i, err := v.entry(path)
	if err != nil {
		return time.Time{}, false, err
	}
	t, ok = expiryOf(&g.Entries[i].Times)
	return t, ok, nil
}

// SetExpiry sets the expiry of an entry to the end of the given day (UTC), or, with the zero time, makes the entry not expire. A change that alters
// nothing writes nothing; a real change first saves the old version into the entry's history.
func (v *Vault) SetExpiry(path string, day time.Time) error {
	g, i, err := v.entry(path)
	if err != nil {
		return err
	}
	e := &g.Entries[i]
	cur, on := expiryOf(&e.Times)
	if day.IsZero() {
		if !on && !e.Times.Expires.Bool {
			return nil
		}
		v.snapshot(e)
		e.Times.Expires = boolW(false)
		v.touch(e)
		return nil
	}
	end := ExpiryEnd(day)
	if on && cur.Equal(end) {
		return nil
	}
	v.snapshot(e)
	t := now(v)
	t.Time = end
	e.Times.ExpiryTime = &t
	e.Times.Expires = boolW(true)
	v.touch(e)
	return nil
}

func expiresOf(e *gokeepasslib.Entry) time.Time {
	t, _ := expiryOf(&e.Times)
	return t
}

func expiryOf(t *gokeepasslib.TimeData) (time.Time, bool) {
	if !t.Expires.Bool || t.ExpiryTime == nil {
		return time.Time{}, false
	}
	return t.ExpiryTime.Time.UTC(), true
}
