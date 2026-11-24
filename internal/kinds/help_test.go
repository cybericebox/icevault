package kinds

import "testing"

// Every field of a built-in kind explains itself in all three languages (what it is, what for, where to get it).
func TestEveryBuiltinFieldHasHelpInAllLanguages(t *testing.T) {
	for _, k := range Builtin().Kinds() {
		for _, f := range k.Fields {
			for _, l := range []string{"en", "uk", "ru"} {
				if len(f.Help[l]) < 20 {
					t.Errorf("%s.%s: no %s help", k.ID, f.Name, l)
				}
			}
		}
	}
}
