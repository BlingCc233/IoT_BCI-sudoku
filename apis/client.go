package apis

import (
	"context"
	"fmt"
	"net"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/mux"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/uot"
)

func Dial(ctx context.Context, addr string, cfg *ClientConfig) (net.Conn, *iotbci.HandshakeMeta, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("nil client config")
	}
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	conn, meta, err := iotbci.ClientHandshake(ctx, raw, cfg.toOptions())
	if err != nil {
		_ = raw.Close()
		return nil, nil, err
	}
	return conn, meta, nil
}

func DialMux(ctx context.Context, addr string, cfg *ClientConfig, mc mux.Config) (*mux.Session, *iotbci.HandshakeMeta, error) {
	conn, meta, err := Dial(ctx, addr, cfg)
	if err != nil {
		return nil, nil, err
	}
	sess, err := mux.Dial(conn, mc)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return sess, meta, nil
}

func DialUoT(ctx context.Context, addr string, cfg *ClientConfig) (net.PacketConn, *iotbci.HandshakeMeta, error) {
	conn, meta, err := Dial(ctx, addr, cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := uot.WritePreface(conn); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return uot.NewPacketConn(conn), meta, nil
}
