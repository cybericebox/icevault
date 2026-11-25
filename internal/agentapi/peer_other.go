//go:build !linux && !darwin

package agentapi

import (
	"errors"
	"net"
)

// PeerOf is not available here: the API is not served.
func PeerOf(net.Conn) (Peer, error) {
	return Peer{}, errors.New("the peer of a connection cannot be read on this system")
}
