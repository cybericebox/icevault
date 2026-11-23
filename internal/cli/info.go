package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// The info file next to the vault (<vault>.info.json) holds no secret: which environments the vault has, the copy destinations and the copies made.
// It is read and written as a generic map so a key this program does not know survives.

const infoSuffix = ".info.json"

const copyFreshDays = 7

type info map[string]any

func infoPath(v string) string { return v + infoSuffix }

func readInfo(v string) info {
	data, err := os.ReadFile(infoPath(v))
	if err != nil {
		return nil
	}
	m := info{}
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	if _, ok := m["sealed"].(map[string]any); !ok {
		m["sealed"] = map[string]any{}
	}
	if _, ok := m["copies"].([]any); !ok {
		m["copies"] = []any{}
	}
	return m
}

func freshInfo() info { return info{"sealed": map[string]any{}, "copies": []any{}} }

func writeInfo(v string, m info) error {
	data, err := json.MarshalIndent(m, "", "  ") // map keys come out sorted
	if err != nil {
		return err
	}
	path := infoPath(v)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func nowStamp() string { return time.Now().UTC().Format("2006-01-02T15:04:05Z") }

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (m info) destinations() []string {
	var out []string
	if l, ok := m["destinations"].([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func (m info) copies() []map[string]any {
	var out []map[string]any
	if l, ok := m["copies"].([]any); ok {
		for _, x := range l {
			if c, ok := x.(map[string]any); ok {
				out = append(out, c)
			}
		}
	}
	return out
}

func (m info) setCopy(to, sha, at string) {
	var keep []any
	for _, c := range m.copies() {
		if c["to"] != to {
			keep = append(keep, c)
		}
	}
	m["copies"] = append(keep, map[string]any{"to": to, "sha256": sha, "at": at})
}

func requireVault(v string) error {
	if st, err := os.Stat(v); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("no vault at %s: `icevault init-vault` for a first setup, or copy your vault file there (ICEVAULT_VAULT names another path)", v)
	}
	return nil
}

func copyDest(v, dir string) string { return filepath.Join(dir, filepath.Base(v)) }

// copyFileSafely is one encrypted copy: a temp name, fsync, sha256 check, the previous copy kept as <name>.prev, then an atomic rename.
func copyFileSafely(src, dir, name, sha string) error {
	dst := filepath.Join(dir, name)
	tmp := dst + ".tmp-copy"
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if got, _ := sha256File(tmp); got != sha {
		_ = os.Remove(tmp)
		return errors.New("the copy does not match the vault")
	}
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, dst+".prev"); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	return os.Rename(tmp, dst)
}

func makeCopies(v string, out io.Writer) []string {
	m := readInfo(v)
	dests := m.destinations()
	if len(dests) == 0 {
		return nil
	}
	sha, err := sha256File(v)
	if err != nil {
		return nil
	}
	var done []string
	type failure struct {
		dir string
		err error
	}
	var failed []failure
	for _, d := range dests {
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			continue
		}
		if have, err := sha256File(copyDest(v, d)); err == nil && have == sha {
			continue
		}
		if err := copyFileSafely(v, d, filepath.Base(v), sha); err != nil {
			failed = append(failed, failure{d, err})
			continue
		}
		done = append(done, d)
	}
	if len(done) > 0 {
		m = readInfo(v)
		if m == nil {
			m = freshInfo()
		}
		stamp := nowStamp()
		for _, d := range done {
			m.setCopy(d, sha, stamp)
		}
		_ = writeInfo(v, m)
		fmt.Fprintf(out, "vault copy written to: %s\n", join(done, ", "))
	}
	for _, f := range failed {
		fmt.Fprintf(out, "vault copy to %s FAILED (%v)\n", f.dir, f.err)
	}
	return done
}

func join(l []string, sep string) string {
	s := ""
	for i, x := range l {
		if i > 0 {
			s += sep
		}
		s += x
	}
	return s
}

type copyRow struct {
	path        string
	reachable   bool
	otherVolume bool
	at, sha     string
	same        bool
}

func copiesStatus(v string) []copyRow {
	m := readInfo(v)
	cur, _ := sha256File(v)
	var rows []copyRow
	for _, d := range m.destinations() {
		st, err := os.Stat(d)
		r := copyRow{path: d, reachable: err == nil && st.IsDir()}
		f := copyDest(v, d)
		if fst, err := os.Stat(f); r.reachable && err == nil {
			r.sha, _ = sha256File(f)
			r.at = fst.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		}
		if !r.reachable {
			for _, c := range m.copies() {
				if c["to"] == d {
					r.sha, _ = c["sha256"].(string)
					r.at, _ = c["at"].(string)
				}
			}
		}
		r.otherVolume = r.reachable && !sameVolume(v, d)
		r.same = r.sha != "" && r.sha == cur
		rows = append(rows, r)
	}
	return rows
}

// copiesWarning is one line for an unlock: no destination at all, or none holding a copy newer than a week. "" when all is well.
func copiesWarning(v string, today time.Time) string {
	m := readInfo(v)
	if len(m.destinations()) == 0 {
		return "vault copies: no destination is configured: `icevault copies add DIR` (a folder on another disk or a USB stick)"
	}
	limit := today.Add(-copyFreshDays * 24 * time.Hour)
	for _, r := range copiesStatus(v) {
		if t, err := time.Parse("2006-01-02T15:04:05Z", r.at); err == nil && !t.Before(limit) {
			return ""
		}
	}
	return fmt.Sprintf("vault copies: no destination holds a copy newer than %d days: `icevault copies list`", copyFreshDays)
}

func copyRowLine(r copyRow) string {
	state := "NOT reachable now"
	if r.reachable {
		state = "reachable"
	}
	vol := "volume unknown"
	switch {
	case r.otherVolume:
		vol = "other volume"
	case r.reachable:
		vol = "same volume"
	}
	cp := "no copy there"
	if r.sha != "" {
		same := "DIFFERENT from the vault"
		if r.same {
			same = "same as the vault"
		}
		cp = fmt.Sprintf("%s %s (%s)", r.sha[:12], r.at, same)
	}
	return fmt.Sprintf("  %s: %s, %s; %s", r.path, state, vol, cp)
}
