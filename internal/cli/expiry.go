package cli

import (
	"fmt"
	"io"
	"strconv"

	"github.com/cybericebox/icevault/internal/vmodel"
	"github.com/cybericebox/icevault/pkg/vault"
)

const cmdExpiring = "expiring"

// The expiry commands print where a value lives, its name and its date: never a value.

func itemLine(it vmodel.ExpiryItem) string {
	word := "expires"
	if it.State == "expired" {
		word = "EXPIRED"
	}
	return fmt.Sprintf("%-7s %s  %s: %s", word, it.Date, it.Place, it.Name)
}

// warnExpired tells on stderr which values an export or a session of the environment uses that have expired. It never stops the run and never
// prints a value.
func warnExpired(e *Env, m *vmodel.Vault, env string) {
	x := m.Env(env)
	if x == nil {
		return
	}
	for _, it := range m.ExpiringIn(x, e.Now(), 0) {
		if it.State == "expired" {
			fmt.Fprintf(e.Err, "icevault: WARNING: %s: %s has expired (%s)\n", it.Place, it.Name, it.Date)
		}
	}
}

// warnExpiredVault is warnExpired for a vault that is not loaded as a model yet.
func warnExpiredVault(e *Env, v *vault.Vault, env string) {
	if m, err := vmodel.Load(v); err == nil {
		warnExpired(e, m, env)
	}
}

// printExpiring writes the expired and soon-expiring values of the list ("" heading: none).
func printExpiring(out io.Writer, items []vmodel.ExpiryItem, indent string) {
	for _, it := range items {
		fmt.Fprintf(out, "%s%s\n", indent, itemLine(it))
	}
}

// expiringDays reads --days (default vmodel.SoonDays).
func expiringDays(args []string) (int, error) {
	s := flagVals(cmdExpiring, args)["days"]
	if s == "" {
		return vmodel.SoonDays, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 3650 {
		return 0, &parseErr{msg: "expiring: --days is a number of days, 0 to 3650"}
	}
	return n, nil
}

// runExpiring is `expiring [--days N]`: every value that has expired or expires within N days (default 14), by date.
func runExpiring(e *Env, args []string, out io.Writer, v *vault.Vault) error {
	days, err := expiringDays(args)
	if err != nil {
		return err
	}
	m, err := vmodel.Load(v)
	if err != nil {
		return fail("%v", err)
	}
	items := m.Expiring(e.Now(), days)
	if len(items) == 0 {
		fmt.Fprintf(out, "nothing has expired or expires within %d day(s)\n", days)
		return nil
	}
	printExpiring(out, items, "")
	return nil
}
