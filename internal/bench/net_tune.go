package bench

import "net"

func tuneLowLatencyTCPConn(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok || tc == nil {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetReadBuffer(1 << 20)
	_ = tc.SetWriteBuffer(1 << 20)
}
