package iotbci

import (
	"errors"
	"fmt"
	"net"
)

var (
	ErrProtocolViolation = errors.New("iotbci: protocol violation")
	ErrAuthFailed        = errors.New("iotbci: authentication failed")
	ErrReplayDetected    = errors.New("iotbci: replay detected")
	ErrTimeSkew          = errors.New("iotbci: time skew")
)

// SuspiciousError indicates a potential attack or protocol violation. The Conn field is
// the connection state at the moment the violation was detected, so callers can perform
// fallback/decoy handling without losing already-consumed bytes.
type SuspiciousError struct {
	Err  error
	Conn net.Conn
}

func (e *SuspiciousError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("iotbci suspicious: %v", e.Err)
}

func (e *SuspiciousError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// RecordedConn can return bytes that were already consumed (and possibly buffered) by
// the protocol stack.
type RecordedConn interface {
	net.Conn
	GetBufferedAndRecorded() []byte
}
