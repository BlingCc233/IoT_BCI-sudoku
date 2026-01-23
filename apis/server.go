package apis

import (
	"context"
	"fmt"
	"net"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/mux"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci/uot"
)

func ServerHandshake(ctx context.Context, rawConn net.Conn, cfg *ServerConfig) (net.Conn, *iotbci.HandshakeMeta, error) {
	if rawConn == nil {
		return nil, nil, fmt.Errorf("nil conn")
	}
	if cfg == nil {
		return nil, nil, fmt.Errorf("nil server config")
	}
	return iotbci.ServerHandshake(ctx, rawConn, cfg.toOptions())
}

func AcceptMux(ctx context.Context, rawConn net.Conn, cfg *ServerConfig, mc mux.Config) (*mux.Session, *iotbci.HandshakeMeta, error) {
	conn, meta, err := ServerHandshake(ctx, rawConn, cfg)
	if err != nil {
		return nil, nil, err
	}
	sess, err := mux.Accept(conn, mc)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return sess, meta, nil
}

func AcceptUoT(ctx context.Context, rawConn net.Conn, cfg *ServerConfig) (net.PacketConn, *iotbci.HandshakeMeta, error) {
	conn, meta, err := ServerHandshake(ctx, rawConn, cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := uot.ReadPreface(conn); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return uot.NewPacketConn(conn), meta, nil
}
