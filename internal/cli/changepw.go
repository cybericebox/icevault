package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/cybericebox/icevault/pkg/vault"
)

// change-password: the master password of an existing vault is replaced and the file re-encrypted in place (vault.SetPassword: the atomic save of every
// other write, the key derivation settings and the key file kept). The window comes to ChangePassword with a vault it has open.
//
// What the change leaves behind is dealt with here, in one place: the Touch ID binding (it holds the OLD password: removed), the info file (the date,
// never a secret), the copies of the vault file (they still open with the OLD password: listed, refreshed when asked, never deleted) and the previous
// copy beside the vault file (the same, but the tool's own: removed).

// ChangeReport is what a change left to say.
type ChangeReport struct {
	// TouchIDWasOn: a Touch ID binding of this vault existed and was removed.
	TouchIDWasOn bool
	// TouchIDRemoveFailed: the binding existed and could not be removed completely. It holds the OLD password: TouchIDLeft are its files.
	TouchIDRemoveFailed bool
	TouchIDLeft         []string
	// Refreshed are the standing destinations that got the new file.
	Refreshed []string
	// Stale are the files that still open with the OLD password: copies in the destinations and in the folders of `copies now`, and the previous copy
	// a refresh keeps there. The files are the person's; they are only named.
	Stale []string
}

func cmdChangePassword(args []string, e *Env) error {
	var generate, refresh bool
	if _, err := parse("change-password", args, e, 0, func(fs *flag.FlagSet) {
		fs.BoolVar(&generate, "generate", false, "a random six-word passphrase, shown once and typed back")
		fs.BoolVar(&refresh, "refresh-copies", false, "write the new file to the standing copy destinations now")
	}); err != nil {
		return err
	}
	path, err := vaultPath(e)
	if err != nil {
		return err
	}
	// every refusal that the files alone decide comes before the first prompt
	if err := requireVault(path); err != nil {
		return err
	}
	kf := e.Getenv("ICEVAULT_KEYFILE")
	if kf != "" {
		if _, err := os.Stat(kf); err != nil {
			return fail("the key file %s does not exist (the vault needs it)", kf)
		}
	}
	// the current password is typed: the one behind Touch ID is not taken here
	cur, err := e.Ask("Current vault password: ")
	defer wipeBytes(cur)
	if err != nil {
		return err
	}
	c := vault.Credentials{Password: append([]byte(nil), cur...), KeyFile: kf}
	v, err := vault.Open(path, c)
	c.Wipe()
	if err != nil {
		return fail("%v", err)
	}
	defer v.Close()
	var next []byte
	if generate {
		next, err = e.generatedPassword()
	} else {
		next, err = e.askPasswordPair(kf, "New vault password: ", "Repeat the new password: ")
	}
	defer wipeBytes(next)
	if err != nil {
		return err
	}
	if string(next) == string(cur) {
		return fail("the new password is the same as the current one; nothing was changed")
	}
	rep, err := e.ChangePassword(v, next, kf, refresh, e.Out)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.Out, "the master password of %s was changed (the vault file was saved with the new one; the old one no longer opens it)\n", path)
	if rep.TouchIDRemoveFailed {
		fmt.Fprintf(e.Out, "WARNING: the Touch ID binding of the old password could not be removed; it no longer opens the vault. Delete these files, or run `touchid disable`:\n")
		for _, f := range rep.TouchIDLeft {
			fmt.Fprintf(e.Out, "  %s\n", f)
		}
	} else if rep.TouchIDWasOn {
		fmt.Fprintln(e.Out, "Touch ID is off; `touchid enable` stores the new password")
	}
	e.printStale(rep, path, refresh)
	return nil
}

// printStale says which files still open with the old password, and how to bring the standing copies up to date.
func (e *Env) printStale(rep *ChangeReport, path string, refreshed bool) {
	if len(rep.Stale) == 0 {
		return
	}
	fmt.Fprintln(e.Out, "these copies of the vault still open with the OLD password (nothing was deleted):")
	for _, f := range rep.Stale {
		fmt.Fprintf(e.Out, "  %s\n", f)
	}
	if !refreshed && len(readInfo(path).destinations()) > 0 {
		fmt.Fprintln(e.Out, "the standing copies follow at the next write, or now: run `change-password --refresh-copies` next time, or `icevault copies now DIR` for one of them")
	}
}

// askPasswordPair is askNewPassword with the words of the prompts the caller chooses.
func (e *Env) askPasswordPair(keyFile, first, again string) ([]byte, error) {
	pw, err := e.Ask(first)
	if err != nil {
		return nil, err
	}
	second, err := e.Ask(again)
	if err != nil {
		return pw, err
	}
	defer wipeBytes(second)
	if string(pw) != string(second) {
		return pw, fail("the passwords do not match; nothing was changed")
	}
	if len(pw) == 0 && keyFile == "" {
		return pw, fail("an empty password needs a key file (ICEVAULT_KEYFILE); nothing was changed")
	}
	if err := checkNewPassword(pw, keyFile); err != nil {
		return pw, changedMessage(err)
	}
	return pw, nil
}

// changedMessage turns the "nothing was made" of the policy into the words of a change.
func changedMessage(err error) error {
	const made = "; nothing was made"
	if m := err.Error(); len(m) > len(made) && m[len(m)-len(made):] == made {
		return fail("%s; nothing was changed", m[:len(m)-len(made)])
	}
	return err
}

// ChangePassword replaces the master password of the open vault v with next and cleans up behind it. The policy of a new password decides first: a
// refusal writes nothing. The caller has checked the current password (it opened v) and wipes next. out receives the lines of a copy refresh. The
// window and change-password both come here.
func (e *Env) ChangePassword(v *vault.Vault, next []byte, keyFile string, refresh bool, out io.Writer) (*ChangeReport, error) {
	if err := checkNewPassword(next, keyFile); err != nil {
		return nil, changedMessage(err)
	}
	path := v.Path()
	prevLeft, err := v.SetPassword(next)
	if err != nil {
		return nil, fmt.Errorf("the password was not changed (the vault file is as it was): %w", err)
	}
	rep := &ChangeReport{}
	rep.TouchIDWasOn, rep.TouchIDLeft = e.touchIDRemove(path)
	rep.TouchIDRemoveFailed = len(rep.TouchIDLeft) > 0
	m := readInfo(path)
	if m == nil {
		m = freshInfo()
	}
	m["password_changed"] = nowStamp()
	_ = writeInfo(path, m) // the date is a note: the change itself is done
	if refresh {
		rep.Refreshed = makeCopies(path, out)
	}
	rep.Stale = staleCopies(path)
	if prevLeft != "" { // the tool's own previous copy could not be removed: it opens with the old password like the copies
		rep.Stale = append([]string{prevLeft}, rep.Stale...)
	}
	return rep, nil
}

// touchIDRemove deletes the Touch ID binding of the vault (it stores the old password). wasOn says there was one; left are its files that could not be
// removed (the binding still holds the old password).
func (e *Env) touchIDRemove(vaultFile string) (wasOn bool, left []string) {
	e.touchIDMigrate(vaultFile)
	k, b := e.touchIDFiles(vaultFile)
	for _, f := range []string{k, b} {
		if _, err := os.Lstat(f); err != nil {
			continue
		}
		wasOn = true
		if os.Remove(f) != nil {
			left = append(left, f)
		}
	}
	return wasOn, left
}

// staleCopies names the files of the copies of the vault that do not hold the current vault file: in the standing destinations and in the folders
// `copies now` wrote to, the copy and its previous copy.
func staleCopies(path string) []string {
	cur, err := sha256File(path)
	if err != nil {
		return nil
	}
	m := readInfo(path)
	dirs := map[string]bool{}
	for _, d := range m.destinations() {
		dirs[d] = true
	}
	for _, c := range m.copies() {
		if d, ok := c["to"].(string); ok && d != "" {
			dirs[d] = true
		}
	}
	var out []string
	for d := range dirs {
		f := copyDest(path, d)
		for _, cand := range []string{f, f + ".prev"} {
			if filepath.Clean(cand) == filepath.Clean(path) {
				continue
			}
			if sum, err := sha256File(cand); err == nil && sum != cur {
				out = append(out, cand)
			}
		}
	}
	sort.Strings(out)
	return out
}

// CopyDestinations are the standing copy destinations of the vault (the window offers to refresh them after a change).
func CopyDestinations(vaultFile string) []string { return readInfo(vaultFile).destinations() }

// TouchIDBound says whether a Touch ID binding of the vault exists on this Mac (the files are there), whatever the platform flag says: the change of a
// password removes it.
func (e *Env) TouchIDBound(vaultFile string) bool {
	e.touchIDMigrate(vaultFile)
	k, b := e.touchIDFiles(vaultFile)
	return isFile(k) && isFile(b)
}
