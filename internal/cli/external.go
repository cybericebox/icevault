package cli

import (
	"bufio"
	"encoding/json"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"

	"github.com/cybericebox/icevault/internal/model"
	"github.com/cybericebox/icevault/internal/vmodel"
)

// `icevault external serve`: one connection the project description serves (serve-as) as a small key/value store for a calling program. The
// vault is unlocked ONCE, when the first message arrives; the caller sends JSON lines on stdin and reads JSON
// lines on stdout. A value travels only on those two pipes: never in an argument, never to a terminal (the command refuses to run when stdin or stdout is a terminal),
// never in an error. The password is asked on the controlling terminal (/dev/tty), not on the pipe; Touch ID works as everywhere.
//
// Messages (one JSON object per line):
//   {"op":"open","name":"monitor","title":"Monitor","keys":{"API_KEY":"secret"},"help":{"API_KEY":"what it is"}}          -> {"ok":true}
//   {"op":"get","group":"ops","key":"API_KEY"}                                                                         -> {"ok":true,"value":"..."} ("" when the entry does not exist)
//   {"op":"put","group":"ops","key":"API_KEY","value":"..."}                                                           -> {"ok":true}   (saved before the answer)
//   {"op":"close"}                                                                                                    -> {"ok":true}   (copies of the vault are made when it changed)
// An error answers {"ok":false,"error":"one line"}. End of input counts as close.

type extMsg struct {
	Op    string            `json:"op"`
	Name  string            `json:"name"`
	Title string            `json:"title"`
	Group string            `json:"group"`
	Key   string            `json:"key"`
	Value string            `json:"value"`
	Keys  map[string]string `json:"keys"`
	Help  map[string]string `json:"help"`
}

type extReply struct {
	OK    bool   `json:"ok"`
	Value string `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
}

// askConsole reads a password without echo from the controlling terminal, for a program whose stdin and stdout are pipes.
func askConsole(prompt string) ([]byte, error) {
	name := "/dev/tty"
	if runtime.GOOS == "windows" {
		name = "CONIN$"
	}
	f, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return nil, errExit{NeedsOwner}
	}
	defer func() { _ = f.Close() }()
	fd := int(f.Fd())
	if !term.IsTerminal(fd) {
		return nil, errExit{NeedsOwner}
	}
	_, _ = f.WriteString(prompt)
	pw, err := term.ReadPassword(fd)
	_, _ = f.WriteString("\n")
	if err != nil {
		return nil, errExit{"the password could not be read: " + err.Error()}
	}
	return pw, nil
}

func cmdExternal(args []string, e *Env) error {
	in := e.In
	if in == nil {
		in = os.Stdin
	}
	if e.AskConsole != nil {
		e.Ask, e.TouchID = e.AskConsole, touchIDPlatform
	}
	if len(args) != 1 || args[0] != "serve" {
		return &parseErr{msg: "external needs serve"}
	}
	if e.StdioIsTerminal != nil && e.StdioIsTerminal() {
		return fail("external serve talks JSON lines to a program on stdin and stdout; it is not for a terminal (a value would be shown there)")
	}
	r := bufio.NewReader(in)
	enc := json.NewEncoder(e.Out)
	reply := func(x extReply) { _ = enc.Encode(x) }
	read := func() (*extMsg, error) {
		line, err := r.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			return nil, err
		}
		var m extMsg
		if jerr := json.Unmarshal(line, &m); jerr != nil {
			wipe(line)
			return &extMsg{Op: "?"}, nil
		}
		wipe(line)
		return &m, nil
	}
	first, err := read()
	if err != nil || first.Op != "open" {
		return fail("the first message is {\"op\":\"open\", ...}")
	}
	if !model.NameRE.MatchString(first.Name) || len(first.Keys) == 0 {
		return fail("open needs a system name (a-z 0-9 _ -) and the keys")
	}
	for k, v := range first.Keys {
		if !model.KeyRE.MatchString(k) || !model.ValidVis(v) {
			return fail("the keys are KEY: plain|secret|sealed")
		}
	}
	path, err := vaultPath(e)
	if err != nil {
		return err
	}
	if !isFile(path) || e.Getenv(noVaultVar) != "" {
		return fail("there is no vault at %s: `icevault init-vault` makes it", path)
	}
	v, err := unlock(path, e)
	if err != nil {
		return err
	}
	defer v.Close()
	if !vmodel.IsModel(v) {
		return errOldLayout(v)
	}
	plat, perr := loadProject(e)
	if perr != nil {
		return perr
	}
	w, werr := modelWriter(e, v, plat)
	if werr != nil {
		return werr
	}
	var k vaultStore = w
	snap := w.Compat().Snap
	refreshInfo(path, plat, snap)
	before, _ := sha256File(path)
	store := model.NewStore(k, snap, nil)
	closed := false
	finish := func() {
		if !closed {
			closed = true
			afterChange(path, before, e.Err) // the copies' lines go to stderr: stdout is the protocol
		}
	}
	defer finish()
	reply(extReply{OK: true})
	for {
		m, err := read()
		if err != nil || m.Op == "close" {
			if m != nil && m.Op == "close" {
				finish()
				reply(extReply{OK: true})
			}
			return nil
		}
		if (m.Op == "get" || m.Op == "put") && !validGroup(m.Group) {
			reply(extReply{Error: "the group is names of letters, digits, . _ - separated by /"})
			continue
		}
		switch m.Op {
		case "get":
			val := ""
			if it := snap.Item(model.SecExternal, first.Name); it != nil {
				if en := it.Find(m.Group, m.Key); en != nil {
					val = en.Value
				}
			}
			reply(extReply{OK: true, Value: val})
		case "put":
			vis, ok := first.Keys[m.Key]
			if !ok {
				reply(extReply{Error: m.Key + " is not a key of " + first.Name})
				continue
			}
			if err := externalPut(store, k, snap, first, m, vis); err != nil {
				reply(extReply{Error: err.Error()})
				continue
			}
			reply(extReply{OK: true})
		default:
			reply(extReply{Error: "unknown op"})
		}
	}
}

func externalPut(s *model.Store, k vaultStore, snap *model.Snapshot, open *extMsg, m *extMsg, vis string) error {
	it := snap.Item(model.SecExternal, open.Name)
	if it != nil {
		if en := it.Find(m.Group, m.Key); en != nil {
			if err := k.SetPassword(en.Path, m.Value); err != nil {
				return err
			}
			en.Value, en.Changed = m.Value, model.NowUTC()
			return k.Commit()
		}
	}
	it, err := s.EnsureItem(model.SecExternal, open.Name, open.Title)
	if err != nil {
		return err
	}
	path := model.VarEntry(model.SecExternal, open.Name, m.Group, m.Key)
	if err := s.EnsureGroupPath(path); err != nil {
		return err
	}
	notes, err := model.EntryNotes(model.ManagedOwner, vis, nil, open.Help[m.Key], "owner")
	if err != nil {
		return err
	}
	pw := m.Value
	if err := k.Add(path, notes, &pw); err != nil {
		return err
	}
	en := model.NewEntry(m.Key, m.Value, m.Group, path)
	en.Managed, en.Vis, en.Title, en.Description, en.VisBy, en.Changed, en.Notes = model.ManagedOwner, vis, m.Key, open.Help[m.Key], "owner", model.NowUTC(), notes
	it.Entries = append(it.Entries, en)
	return k.Commit()
}

func validGroup(g string) bool {
	if g == "" || len(g) > 200 || strings.HasPrefix(g, "/") || model.IsReserved(strings.SplitN(g, "/", 2)[0]) {
		return false
	}
	for _, p := range strings.Split(g, "/") {
		if !model.PathPart.MatchString(p) {
			return false
		}
	}
	return true
}
