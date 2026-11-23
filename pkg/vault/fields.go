package vault

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/tobischo/gokeepasslib/v3"
)

// Custom string fields ("additional attributes" in KeePassXC), the custom data of the database, and the few tree operations the vault model needs.
// A custom field is any string value of an entry other than the five standard ones; KeePass clients show and keep them. A protected field is kept
// encrypted in memory by the client and masked in its screen, as the password is.

var standardFields = map[string]bool{"Title": true, "UserName": true, "Password": true, "URL": true, "Notes": true}

// ErrStandardField is the refusal of a custom field that has the name of a standard one.
var ErrStandardField = errors.New("a custom field cannot have the name of a standard field (Title, UserName, Password, URL, Notes)")

// Field is a custom string field of an entry.
type Field struct {
	Value     string
	Protected bool
}

// Fields returns the custom string fields of an entry (protected ones included: the caller decides what to show).
func (v *Vault) Fields(path string) (map[string]Field, error) {
	g, i, err := v.entry(path)
	if err != nil {
		return nil, err
	}
	out := map[string]Field{}
	for _, d := range g.Entries[i].Values {
		if !standardFields[d.Key] {
			out[d.Key] = Field{Value: d.Value.Content, Protected: d.Value.Protected.Bool}
		}
	}
	return out, nil
}

// SetFields sets custom string fields of an entry (an empty value is a field with an empty value; RemoveField removes one). Fields not named are left
// alone. A change that alters nothing writes nothing; a real change first saves the old version into the entry's history.
func (v *Vault) SetFields(path string, fields map[string]Field) error {
	for k := range fields {
		if standardFields[k] || k == "" {
			return fmt.Errorf("%q: %w", k, ErrStandardField)
		}
	}
	g, i, err := v.entry(path)
	if err != nil {
		return err
	}
	e := &g.Entries[i]
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	changed := false
	for _, k := range keys {
		f := fields[k]
		j := e.GetIndex(k)
		if j < 0 || e.Values[j].Value.Content != f.Value || e.Values[j].Value.Protected.Bool != f.Protected {
			changed = true
		}
	}
	if !changed {
		return nil
	}
	v.snapshot(e)
	for _, k := range keys {
		f := fields[k]
		j := e.GetIndex(k)
		switch {
		case j >= 0:
			e.Values[j].Value.Content, e.Values[j].Value.Protected = f.Value, boolW(f.Protected)
		default:
			e.Values = append(e.Values, gokeepasslib.ValueData{Key: k, Value: gokeepasslib.V{Content: f.Value, Protected: boolW(f.Protected)}})
		}
	}
	v.touch(e)
	return nil
}

// RemoveField removes a custom string field of an entry (none of that name: nothing changes).
func (v *Vault) RemoveField(path, name string) error {
	if standardFields[name] {
		return fmt.Errorf("%q: %w", name, ErrStandardField)
	}
	g, i, err := v.entry(path)
	if err != nil {
		return err
	}
	e := &g.Entries[i]
	j := e.GetIndex(name)
	if j < 0 {
		return nil
	}
	v.snapshot(e)
	e.Values = append(e.Values[:j], e.Values[j+1:]...)
	v.touch(e)
	return nil
}

// RemoveEmptyGroup deletes a group that holds no entry and no group (for good: there is nothing in it to keep). A group with something in it is refused.
func (v *Vault) RemoveEmptyGroup(path string) error {
	parts := split(path)
	if len(parts) == 0 {
		return errors.New("the root group cannot be removed")
	}
	parent, err := v.group(strings.Join(parts[:len(parts)-1], "/"))
	if err != nil {
		return err
	}
	for i := range parent.Groups {
		g := &parent.Groups[i]
		if g.Name != parts[len(parts)-1] {
			continue
		}
		if len(g.Entries) > 0 || len(g.Groups) > 0 {
			return fmt.Errorf("group %q is not empty", path)
		}
		parent.Groups = append(parent.Groups[:i], parent.Groups[i+1:]...)
		return nil
	}
	return fmt.Errorf("group %q: %w", path, ErrNotFound)
}

// UUIDOf is the UUID of an entry (32 lower-case hex characters), the stable name a reference uses.
func (v *Vault) UUIDOf(path string) (string, error) {
	g, i, err := v.entry(path)
	if err != nil {
		return "", err
	}
	return uuidText(g.Entries[i].UUID), nil
}

// MetaValue is a value of the custom data of the database ("" when it is not set).
func (v *Vault) MetaValue(key string) string {
	for _, c := range v.db.Content.Meta.CustomData {
		if c.Key == key {
			return c.Value
		}
	}
	return ""
}

// SetMetaValue sets (or, with "", removes) a value of the custom data of the database. KeePass clients keep it on every save.
func (v *Vault) SetMetaValue(key, value string) {
	meta := v.db.Content.Meta
	for i, c := range meta.CustomData {
		if c.Key == key {
			if value == "" {
				meta.CustomData = append(meta.CustomData[:i], meta.CustomData[i+1:]...)
			} else {
				meta.CustomData[i].Value = value
			}
			return
		}
	}
	if value != "" {
		meta.CustomData = append(meta.CustomData, gokeepasslib.CustomData{Key: key, Value: value})
	}
}

// RecycleGroup moves a group with everything in it into the recycle bin (made when missing), as KeePass does when a group is deleted: a KeePass
// client restores it from there. A group of that name already in the bin gets a number.
func (v *Vault) RecycleGroup(path string) error {
	parts := split(path)
	if len(parts) == 0 {
		return errors.New("the root group cannot be recycled")
	}
	if _, err := v.group(path); err != nil {
		return err
	}
	if bin := v.recycleBin(false); bin != nil && strings.HasPrefix(strings.Join(parts, "/")+"/", bin.Name+"/") {
		return errors.New("the group is in the recycle bin already")
	}
	bin := v.recycleBin(true)
	name := parts[len(parts)-1]
	for n := 2; findGroup(bin, name) != nil; n++ {
		name = fmt.Sprintf("%s %d", parts[len(parts)-1], n)
	}
	return v.Move(strings.Join(parts, "/"), bin.Name+"/"+name)
}
