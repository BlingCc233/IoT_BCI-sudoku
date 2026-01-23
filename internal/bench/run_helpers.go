package bench

import (
	"io"
	"net"
	"time"
)

func netPipe() (net.Conn, net.Conn) {
	return net.Pipe()
}

func readFull(r io.Reader, b []byte) error {
	_, err := io.ReadFull(r, b)
	return err
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

func avgDuration(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	var sum time.Duration
	for _, x := range d {
		sum += x
	}
	return sum / time.Duration(len(d))
}
