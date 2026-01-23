package mux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	frameOpen  byte = 0x01
	frameData  byte = 0x02
	frameClose byte = 0x03
	frameReset byte = 0x04
)

const (
	headerSize = 1 + 4 + 4
)

type Config struct {
	MaxFrameSize            int
	MaxDataPayload          int
	MaxStreams              int
	MaxQueuedBytesPerStream int
	MaxQueuedBytesTotal     int
}

func (c *Config) setDefaults() {
	if c.MaxFrameSize <= 0 {
		c.MaxFrameSize = 256 * 1024
	}
	if c.MaxDataPayload <= 0 {
		c.MaxDataPayload = 32 * 1024
	}
	if c.MaxStreams <= 0 {
		c.MaxStreams = 1024
	}
	if c.MaxQueuedBytesPerStream <= 0 {
		c.MaxQueuedBytesPerStream = 512 * 1024
	}
	if c.MaxQueuedBytesTotal <= 0 {
		c.MaxQueuedBytesTotal = 8 * 1024 * 1024
	}
}

type Session struct {
	conn net.Conn
	cfg  Config

	writeMu sync.Mutex

	streamsMu sync.Mutex
	streams   map[uint32]*Stream
	nextID    uint32

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error

	acceptCh chan accepted

	queuedTotal atomic.Int64
}

type accepted struct {
	st      *Stream
	payload []byte
}

func Dial(conn net.Conn, cfg Config) (*Session, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil conn")
	}
	cfg.setDefaults()
	if err := WritePreface(conn); err != nil {
		return nil, err
	}
	s := &Session{
		conn:    conn,
		cfg:     cfg,
		streams: make(map[uint32]*Stream),
		closed:  make(chan struct{}),
	}
	go s.readLoop()
	return s, nil
}

func Accept(conn net.Conn, cfg Config) (*Session, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil conn")
	}
	cfg.setDefaults()
	if err := ReadPreface(conn); err != nil {
		return nil, err
	}
	s := &Session{
		conn:     conn,
		cfg:      cfg,
		streams:  make(map[uint32]*Stream),
		closed:   make(chan struct{}),
		acceptCh: make(chan accepted, cfg.MaxStreams),
	}
	go s.readLoop()
	return s, nil
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.closeWithError(io.ErrClosedPipe)
	return nil
}

func (s *Session) Closed() <-chan struct{} {
	if s == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return s.closed
}

func (s *Session) closedErr() error {
	s.streamsMu.Lock()
	err := s.closeErr
	s.streamsMu.Unlock()
	if err == nil {
		return io.ErrClosedPipe
	}
	return err
}

func (s *Session) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *Session) closeWithError(err error) {
	if err == nil {
		err = io.ErrClosedPipe
	}
	s.closeOnce.Do(func() {
		s.streamsMu.Lock()
		if s.closeErr == nil {
			s.closeErr = err
		}
		streams := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.streams = make(map[uint32]*Stream)
		s.streamsMu.Unlock()

		for _, st := range streams {
			st.closeNoSend(err)
		}

		close(s.closed)
		_ = s.conn.Close()
	})
}

func (s *Session) registerStream(st *Stream) {
	s.streamsMu.Lock()
	s.streams[st.id] = st
	s.streamsMu.Unlock()
}

func (s *Session) getStream(id uint32) *Stream {
	s.streamsMu.Lock()
	st := s.streams[id]
	s.streamsMu.Unlock()
	return st
}

func (s *Session) removeStream(id uint32) {
	s.streamsMu.Lock()
	delete(s.streams, id)
	s.streamsMu.Unlock()
}

func (s *Session) nextStreamID() uint32 {
	s.streamsMu.Lock()
	s.nextID++
	id := s.nextID
	if id == 0 {
		s.nextID++
		id = s.nextID
	}
	s.streamsMu.Unlock()
	return id
}

func (s *Session) tryAddQueued(n int) bool {
	if n <= 0 {
		return true
	}
	limit := int64(s.cfg.MaxQueuedBytesTotal)
	for {
		cur := s.queuedTotal.Load()
		next := cur + int64(n)
		if next > limit {
			return false
		}
		if s.queuedTotal.CompareAndSwap(cur, next) {
			return true
		}
	}
}

func (s *Session) subQueued(n int) {
	if n <= 0 {
		return
	}
	s.queuedTotal.Add(-int64(n))
}

func (s *Session) sendFrame(frameType byte, streamID uint32, payload []byte) error {
	if s.isClosed() {
		return s.closedErr()
	}
	if len(payload) > s.cfg.MaxFrameSize {
		return fmt.Errorf("mux payload too large: %d", len(payload))
	}

	var header [headerSize]byte
	header[0] = frameType
	binary.BigEndian.PutUint32(header[1:5], streamID)
	binary.BigEndian.PutUint32(header[5:9], uint32(len(payload)))

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := writeFull(s.conn, header[:]); err != nil {
		s.closeWithError(err)
		return err
	}
	if len(payload) > 0 {
		if err := writeFull(s.conn, payload); err != nil {
			s.closeWithError(err)
			return err
		}
	}
	return nil
}

func (s *Session) sendReset(streamID uint32, msg string) {
	if msg == "" {
		msg = "reset"
	}
	_ = s.sendFrame(frameReset, streamID, []byte(msg))
	_ = s.sendFrame(frameClose, streamID, nil)
}

// OpenStream opens a new outgoing logical stream with optional open payload.
func (s *Session) OpenStream(payload []byte) (net.Conn, error) {
	if s == nil {
		return nil, fmt.Errorf("nil session")
	}
	if s.acceptCh != nil {
		return nil, fmt.Errorf("OpenStream only valid on client sessions")
	}
	if s.isClosed() {
		return nil, s.closedErr()
	}
	if len(payload) > s.cfg.MaxFrameSize {
		return nil, fmt.Errorf("open payload too large: %d", len(payload))
	}

	// Stream count limit.
	s.streamsMu.Lock()
	if len(s.streams) >= s.cfg.MaxStreams {
		s.streamsMu.Unlock()
		return nil, fmt.Errorf("too many streams")
	}
	s.streamsMu.Unlock()

	streamID := s.nextStreamID()
	st := newStream(s, streamID)
	s.registerStream(st)

	if err := s.sendFrame(frameOpen, streamID, payload); err != nil {
		st.closeNoSend(err)
		s.removeStream(streamID)
		return nil, err
	}
	return st, nil
}

// AcceptStream waits for the next incoming stream. Only valid on server sessions.
func (s *Session) AcceptStream(ctx context.Context) (net.Conn, []byte, error) {
	if s == nil {
		return nil, nil, fmt.Errorf("nil session")
	}
	if s.acceptCh == nil {
		return nil, nil, fmt.Errorf("AcceptStream only valid on server sessions")
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-s.closed:
		return nil, nil, s.closedErr()
	case a := <-s.acceptCh:
		return a.st, a.payload, nil
	}
}

func (s *Session) readLoop() {
	var header [headerSize]byte
	for {
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			s.closeWithError(err)
			return
		}
		frameType := header[0]
		streamID := binary.BigEndian.Uint32(header[1:5])
		n := int(binary.BigEndian.Uint32(header[5:9]))
		if n < 0 || n > s.cfg.MaxFrameSize {
			s.closeWithError(fmt.Errorf("invalid mux frame length: %d", n))
			return
		}

		var payload []byte
		if n > 0 {
			payload = make([]byte, n)
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				s.closeWithError(err)
				return
			}
		}

		switch frameType {
		case frameOpen:
			if s.acceptCh == nil {
				go s.sendReset(streamID, "unexpected open")
				continue
			}
			if streamID == 0 {
				go s.sendReset(streamID, "invalid stream id")
				continue
			}
			s.streamsMu.Lock()
			if len(s.streams) >= s.cfg.MaxStreams {
				s.streamsMu.Unlock()
				go s.sendReset(streamID, "too many streams")
				continue
			}
			if s.streams[streamID] != nil {
				s.streamsMu.Unlock()
				go s.sendReset(streamID, "stream exists")
				continue
			}
			st := newStream(s, streamID)
			s.streams[streamID] = st
			s.streamsMu.Unlock()

			select {
			case s.acceptCh <- accepted{st: st, payload: payload}:
			default:
				st.closeNoSend(errors.New("accept queue full"))
				s.removeStream(streamID)
				go s.sendReset(streamID, "accept queue full")
			}

		case frameData:
			if len(payload) == 0 {
				continue
			}
			if len(payload) > s.cfg.MaxDataPayload {
				go s.sendReset(streamID, "data too large")
				continue
			}
			st := s.getStream(streamID)
			if st == nil {
				continue
			}
			if err := st.enqueue(payload); err != nil {
				st.closeNoSend(err)
				s.removeStream(streamID)
				go s.sendReset(streamID, err.Error())
			}

		case frameClose:
			st := s.getStream(streamID)
			if st == nil {
				continue
			}
			st.closeRemote(io.EOF)
			s.removeStream(streamID)

		case frameReset:
			st := s.getStream(streamID)
			if st == nil {
				continue
			}
			msg := stringsTrimASCII(payload)
			if msg == "" {
				msg = "reset"
			}
			st.closeNoSend(errors.New(msg))
			s.removeStream(streamID)

		default:
			s.closeWithError(fmt.Errorf("unknown mux frame type: %d", frameType))
			return
		}
	}
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

func stringsTrimASCII(b []byte) string {
	i := 0
	j := len(b)
	for i < j {
		c := b[i]
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			break
		}
		i++
	}
	for j > i {
		c := b[j-1]
		if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
			break
		}
		j--
	}
	if i >= j {
		return ""
	}
	out := make([]byte, j-i)
	copy(out, b[i:j])
	return string(out)
}

type Stream struct {
	session *Session
	id      uint32

	mu       sync.Mutex
	cond     *sync.Cond
	closed   bool
	closeErr error

	readBuf []byte
	queue   [][]byte

	queuedBytes int
}

func newStream(session *Session, id uint32) *Stream {
	st := &Stream{
		session: session,
		id:      id,
	}
	st.cond = sync.NewCond(&st.mu)
	return st
}

func (c *Stream) closeRemote(err error) {
	if err == nil {
		err = io.EOF
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	if c.closeErr == nil {
		c.closeErr = err
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *Stream) closeNoSend(err error) {
	if err == nil {
		err = io.EOF
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	if c.closeErr == nil {
		c.closeErr = err
	}
	remaining := c.queuedBytes
	c.queuedBytes = 0
	c.queue = nil
	c.readBuf = nil
	c.cond.Broadcast()
	c.mu.Unlock()

	c.session.subQueued(remaining)
}

func (c *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	for len(c.readBuf) == 0 && len(c.queue) == 0 && !c.closed {
		c.cond.Wait()
	}
	if len(c.readBuf) == 0 && len(c.queue) > 0 {
		c.readBuf = c.queue[0]
		c.queue = c.queue[1:]
	}
	if len(c.readBuf) == 0 && c.closed {
		if c.closeErr == nil {
			return 0, io.ErrClosedPipe
		}
		return 0, c.closeErr
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	c.queuedBytes -= n
	c.session.subQueued(n)
	return n, nil
}

func (c *Stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.session.isClosed() {
		return 0, c.session.closedErr()
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		if c.closeErr == nil {
			return 0, io.ErrClosedPipe
		}
		return 0, c.closeErr
	}

	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > c.session.cfg.MaxDataPayload {
			chunk = p[:c.session.cfg.MaxDataPayload]
		}
		if err := c.session.sendFrame(frameData, c.id, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *Stream) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.closeErr == nil {
		c.closeErr = io.ErrClosedPipe
	}
	remaining := c.queuedBytes
	c.queuedBytes = 0
	c.queue = nil
	c.readBuf = nil
	c.cond.Broadcast()
	c.mu.Unlock()

	c.session.subQueued(remaining)
	_ = c.session.sendFrame(frameClose, c.id, nil)
	c.session.removeStream(c.id)
	return nil
}

func (c *Stream) CloseWrite() error { return c.Close() }
func (c *Stream) CloseRead() error  { return c.Close() }

func (c *Stream) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c *Stream) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (c *Stream) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}
func (c *Stream) SetReadDeadline(time.Time) error  { return nil }
func (c *Stream) SetWriteDeadline(time.Time) error { return nil }

func (c *Stream) enqueue(payload []byte) error {
	if len(payload) <= 0 {
		return nil
	}
	if !c.session.tryAddQueued(len(payload)) {
		return errors.New("queued bytes total limit")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		c.session.subQueued(len(payload))
		return io.ErrClosedPipe
	}
	if c.queuedBytes+len(payload) > c.session.cfg.MaxQueuedBytesPerStream {
		c.session.subQueued(len(payload))
		return errors.New("queued bytes per-stream limit")
	}

	if len(c.readBuf) == 0 && len(c.queue) == 0 {
		c.readBuf = payload
	} else {
		c.queue = append(c.queue, payload)
	}
	c.queuedBytes += len(payload)
	c.cond.Signal()
	return nil
}
