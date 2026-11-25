package agentapi

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Peer is the process on the other end of a connection of the socket, as the system says (not as the client says).
type Peer struct {
	UID    int
	PID    int
	Name   string // the program of PID
	PPID   int
	Parent string // the program that started it (the agent, when the client is the icevault command)
}

// Describe is the line the confirmation shows: the real program and its parent.
func (p Peer) Describe() string {
	s := p.Name + " (pid " + strconv.Itoa(p.PID) + ")"
	if p.Parent != "" {
		s += ", started by " + p.Parent + " (pid " + strconv.Itoa(p.PPID) + ")"
	}
	return s
}

// SameUser says whether the peer is this user.
func (p Peer) SameUser() bool { return p.UID == os.Getuid() }

// programOf asks ps for the parent and the program name of a process; empty when ps is not there.
func programOf(pid int) (ppid int, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "ppid=,comm=").Output() // #nosec G204 -- fixed program, numeric argument
	if err != nil {
		return 0, ""
	}
	f := strings.Fields(strings.TrimSpace(string(out)))
	if len(f) < 2 {
		return 0, ""
	}
	ppid, _ = strconv.Atoi(f[0])
	return ppid, strings.Join(f[1:], " ")
}

func (p *Peer) fill() {
	p.PPID, p.Name = programOf(p.PID)
	if p.Name == "" {
		p.Name = "unknown"
	}
	if p.PPID > 0 {
		_, p.Parent = programOf(p.PPID)
	}
}
