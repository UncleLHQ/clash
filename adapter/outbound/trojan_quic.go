package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/trojan"

	"github.com/quic-go/quic-go"
)

var defaultALPN = []string{"h3"}

type TrojanQuic struct {
	*Base
	instance *trojan.Trojan
	option   *TrojanQuicOption

	sessionManager sessionManager
}

type TrojanQuicOption struct {
	BasicOption
	TrojanOption

	ReduceRTT bool       `proxy:"reduce-rtt,omitempty"`
	MuxOpts   MuxOptions `proxy:"mux-opts,omitempty"`
}

type MuxOptions struct {
	Concurrency int `proxy:"concurrency,omitempty"`
	IdleTimeout int `proxy:"idle-timeout,omitempty"`
}

func (t *TrojanQuic) plainStream(c net.Conn) (net.Conn, error) {
	// using tls tunnel implemented by quic
	return c, nil
}

// StreamConn implements C.ProxyAdapter
func (t *TrojanQuic) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error

	c, err = t.plainStream(c)

	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	err = t.instance.WriteHeader(c, trojan.CommandTCP, serializesSocksAddr(metadata))
	return c, err
}

// DialContext implements C.ProxyAdapter
func (t *TrojanQuic) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	c, err := t.DialQuicContext(ctx, t.Base.DialOptions(opts...))
	if err != nil {
		return nil, fmt.Errorf("%s quic connect error: %w", t.addr, err)
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = t.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, t), err
}

// ListenPacketContext implements C.ProxyAdapter
func (t *TrojanQuic) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	var c net.Conn

	c, err = t.DialQuicContext(ctx, t.Base.DialOptions(opts...))
	if err != nil {
		return nil, fmt.Errorf("%s quic connect error: %w", t.addr, err)
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = t.plainStream(c)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	err = t.instance.WriteHeader(c, trojan.CommandUDP, serializesSocksAddr(metadata))
	if err != nil {
		return nil, err
	}

	pc := t.instance.PacketConn(c)
	return newPacketConn(pc, t), err
}

func NewTrojanQuic(option TrojanQuicOption) (*TrojanQuic, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	tOption := &trojan.Option{
		Password:       option.Password,
		ALPN:           option.ALPN,
		ServerName:     option.Server,
		SkipCertVerify: option.SkipCertVerify,
	}

	if option.SNI != "" {
		tOption.ServerName = option.SNI
	}

	t := &TrojanQuic{
		Base: &Base{
			name:  option.Name,
			addr:  addr,
			tp:    C.Trojan,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		instance: trojan.New(tOption),
		option:   &option,
	}

	quicDialFn := func() (quic.Connection, error) {
		return t.DialQuic(context.Background(), t.Base.DialOptions())
	}

	newSession := func() (*session, error) {
		idleTimeout := 1 * time.Minute
		if option.MuxOpts.IdleTimeout > 0 {
			idleTimeout = time.Duration(option.MuxOpts.IdleTimeout) * time.Second
		}

		concurrency := 8
		if option.MuxOpts.Concurrency > 0 {
			concurrency = option.MuxOpts.Concurrency
		}

		return &session{
			dialFn:       quicDialFn,
			mutex:        new(sync.RWMutex),
			updateTime:   time.Now(),
			idleTimeout:  idleTimeout,
			maxStreamNum: concurrency,
		}, nil
	}

	t.sessionManager = sessionManager{
		ctx:        context.Background(),
		newSession: newSession,
		mutex:      new(sync.Mutex),
	}

	return t, nil
}

func (t *TrojanQuic) DialQuicContext(ctx context.Context, opts []dialer.Option) (_ net.Conn, err error) {
	session, err := t.sessionManager.getSession()
	if err != nil {
		return nil, err
	}

	stream, err := session.newStream()
	if err != nil {
		return nil, fmt.Errorf("%s quic failed to open stream with remote server connect error: %w", t.addr, err)
	}

	return stream, nil
}

func (t *TrojanQuic) DialQuic(ctx context.Context, opts []dialer.Option) (quic.Connection, error) {
	pConn, err := dialer.ListenPacket(ctx, "udp", "", opts...)
	if err != nil {
		return nil, fmt.Errorf("%s listen UDP at localhost once error: %w", t.addr, err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", t.addr)
	if err != nil {
		return nil, err
	}

	alpn := defaultALPN
	if len(t.option.ALPN) != 0 {
		alpn = t.option.ALPN
	}
	serverName := t.option.Server
	if t.option.SNI != "" {
		serverName = t.option.SNI
	}
	tlsConf := &tls.Config{
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: t.option.SkipCertVerify,
		ServerName:         serverName,
	}
	var c quic.Connection
	if t.option.ReduceRTT {
		c, err = quic.DialEarlyContext(ctx, pConn, udpAddr, "", tlsConf, nil)
	} else {
		c, err = quic.DialContext(ctx, pConn, udpAddr, "", tlsConf, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	return c, nil
}

// conn wrap quic.Connection & quic.Stream as tunnel.Conn

type quicStreamConn struct {
	quic.Connection
	quic.Stream

	lock      sync.Mutex
	closeOnce sync.Once
	closeErr  error

	laterClose func()
}

func (q *quicStreamConn) Write(p []byte) (n int, err error) {
	q.lock.Lock()
	defer q.lock.Unlock()
	return q.Stream.Write(p)
}

func (q *quicStreamConn) Close() error {
	q.closeOnce.Do(func() {
		q.closeErr = q.close()
	})
	return q.closeErr
}

func (q *quicStreamConn) close() error {
	if q.laterClose != nil {
		defer time.AfterFunc(10*time.Second, q.laterClose)
	}

	// https://github.com/cloudflare/cloudflared/commit/ed2bac026db46b239699ac5ce4fcf122d7cab2cd
	// Make sure a possible writer does not block the lock forever. We need it, so we can close the writer
	// side of the stream safely.
	_ = q.Stream.SetWriteDeadline(time.Now())

	// This lock is eventually acquired despite Write also acquiring it, because we set a deadline to writes.
	q.lock.Lock()
	defer q.lock.Unlock()

	// We have to clean up the receiving stream ourselves since the Close in the bottom does not handle that.
	q.Stream.CancelRead(0)
	return q.Stream.Close()
}

var _ net.Conn = &quicStreamConn{}

func newStreamConn(c quic.Connection, s quic.Stream, laterClose func()) *quicStreamConn {
	return &quicStreamConn{
		Connection: c,
		Stream:     s,

		laterClose: laterClose,
	}
}

type session struct {
	conn  quic.Connection
	mutex *sync.RWMutex

	dialFn func() (quic.Connection, error)

	updateTime   time.Time
	idleTimeout  time.Duration
	streamNum    int
	maxStreamNum int
}

func (s *session) IsAvailable() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if s.conn == nil {
		return true
	}
	select {
	case <-s.conn.Context().Done():
		return false
	default:
		return s.streamNum < s.maxStreamNum && s.updateTime.Sub(time.Now()) < s.idleTimeout
	}
}

func (s *session) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.conn != nil && s.streamNum == 0 {
		err := s.conn.CloseWithError(0, "quic conn is closing")
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *session) newStream() (*quicStreamConn, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.conn == nil {
		var err error
		s.conn, err = s.dialFn()
		if err != nil {
			return nil, err
		}
	}
	stream, err := s.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	s.streamNum++
	s.updateTime = time.Now()
	return newStreamConn(s.conn, stream, s.closeStream), nil
}

func (s *session) closeStream() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.streamNum--
	if s.streamNum == 0 {
		defer time.AfterFunc(10*time.Second, func() {
			s.Close()
		})
	}
}

type sessionManager struct {
	ctx context.Context

	newSession func() (*session, error)
	session    *session

	mutex *sync.Mutex
}

func (p *sessionManager) getSession() (*session, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.session != nil && p.session.IsAvailable() {
		return p.session, nil
	}

	s, err := p.newSession()
	if err != nil {
		return nil, err
	}

	p.session = s
	return s, nil
}
