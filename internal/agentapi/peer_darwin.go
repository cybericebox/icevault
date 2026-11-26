//go:build darwin

package agentapi

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// PeerOf reads the user and the process of the other end of a unix connection (LOCAL_PEERCRED and LOCAL_PEERPID).
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
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e != nil {
			gerr = e
			return
		}
		pid, e := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if e != nil {
			gerr = e
			return
		}
		p.UID, p.PID = int(cred.Uid), pid
	}); err != nil {
		return Peer{}, err
	}
	if gerr != nil {
		return Peer{}, gerr
	}
	p.fill()
	return p, nil
}
