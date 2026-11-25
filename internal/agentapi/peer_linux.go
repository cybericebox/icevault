//go:build linux

package agentapi

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// PeerOf reads the user and the process of the other end of a unix connection (SO_PEERCRED).
func PeerOf(conn net.Conn) (Peer, error) {
	uc, isUnix := conn.(*net.UnixConn)
	if !isUnix {
		return Peer{}, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var p Peer
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			gerr = e
			return
		}
		p.UID, p.PID = int(cred.Uid), int(cred.Pid)
	}); err != nil {
		return Peer{}, err
	}
	if gerr != nil {
		return Peer{}, gerr
	}
	p.fill()
	return p, nil
}
