package node

import (
	"io"
	"net"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

func HandleSuspicious(wrapper net.Conn, rawConn net.Conn, fallbackAddr string, action string) {
	if rawConn == nil {
		return
	}

	switch action {
	case "silent":
		_, _ = io.Copy(io.Discard, rawConn)
		time.Sleep(2 * time.Second)
		_ = rawConn.Close()
		return
	default:
	}

	if fallbackAddr == "" {
		_ = rawConn.Close()
		return
	}

	dst, err := net.DialTimeout("tcp", fallbackAddr, 3*time.Second)
	if err != nil {
		_ = rawConn.Close()
		return
	}

	var badData []byte
	if wrapper != nil {
		if rc, ok := wrapper.(iotbci.RecordedConn); ok {
			badData = rc.GetBufferedAndRecorded()
		} else if rc, ok := wrapper.(interface{ GetBufferedAndRecorded() []byte }); ok {
			badData = rc.GetBufferedAndRecorded()
		}
	}
	if len(badData) > 0 {
		_ = dst.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_ = writeFull(dst, badData)
		_ = dst.SetWriteDeadline(time.Time{})
	}

	go func() {
		defer dst.Close()
		_, _ = io.Copy(dst, rawConn)
	}()
	go func() {
		defer rawConn.Close()
		_, _ = io.Copy(rawConn, dst)
	}()
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
