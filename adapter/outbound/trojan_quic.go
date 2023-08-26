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

	return t, nil
}

func (t *TrojanQuic) DialQuicContext(ctx context.Context, opts []dialer.Option) (_ net.Conn, err error) {
	conn, err := t.DialQuic(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("%s quic failed to connect with remote server connect error: %w", t.addr, err)
	}

	stream, err := conn.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("%s quic failed to open stream with remote server connect error: %w", t.addr, err)
	}

	return newStreamConn(conn, stream), nil
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

	// https://github.com/cloudflare/cloudflared/commit/ed2bac026db46b239699ac5ce4fcf122d7cab2cd
	// Make sure a possible writer does not block the lock forever. We need it, so we can close the writer
	// side of the stream safely.
	_ = q.Stream.SetWriteDeadline(time.Now())

	// This lock is eventually acquired despite Write also acquiring it, because we set a deadline to writes.
	q.lock.Lock()
	defer q.lock.Unlock()

	// We have to clean up the receiving stream ourselves since the Close in the bottom does not handle that.
	q.Stream.CancelRead(0)
	err := q.Stream.Close()
	if err != nil {
		return err
	}

	return q.Connection.CloseWithError(0, "quic connection closed")
}

var _ net.Conn = &quicStreamConn{}

func newStreamConn(c quic.Connection, s quic.Stream) *quicStreamConn {
	return &quicStreamConn{
		Connection: c,
		Stream:     s,
	}
}
