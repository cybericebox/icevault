package render

import (
	"bufio"
	"os"
	"strings"
)

// ReadSettings reads the KEY=value lines of a settings file (comments and blank lines skipped, a value as ParseValue reads it).
func ReadSettings(p string) (map[string]string, error) {
	f, err := os.Open(p) // #nosec G304 -- a committed settings file of the checkout
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			continue
		}
		v, _ = ParseValue(v)
		out[strings.TrimSpace(k)] = v
	}
	return out, sc.Err()
}
