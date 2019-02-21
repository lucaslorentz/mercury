// This file is adapted from code in the net/http/httputil
// package of the Go standard library, which is by the
// Go Authors, and bears this copyright and license info:
//
//   Copyright 2011 The Go Authors. All rights reserved.
//   Use of this source code is governed by a BSD-style
//   license that can be found in the LICENSE file.
//
// This file has been modified from the standard lib to
// meet the needs of the application.

package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/schubergphilis/mercury/pkg/logging"
)

// onExitFlushLoop is a callback set by tests to detect the state of the
// flushLoop() goroutine.
var onExitFlushLoop func()

// ReverseProxy is an HTTP Handler that takes an incoming request and
// sends it to another server, proxying the response back to the
// client.
type ReverseProxy struct {
	// Director must be a function which modifies
	// the request into a new request to be sent
	// using Transport. Its response is then copied
	// back to the original client unmodified.
	// Director must not access the provided Request
	// after returning.
	Director func(*http.Request)

	// The transport used to perform proxy requests.
	// If nil, http.DefaultTransport is used.
	Transport http.RoundTripper

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	FlushInterval time.Duration

	// ErrorLog specifies an optional logger for errors
	// that occur when attempting to proxy the request.
	// If nil, logging goes to os.Stderr via the log package's
	// standard logger.
	ErrorLog *log.Logger

	// BufferPool optionally specifies a buffer pool to
	// get byte slices for use by io.CopyBuffer when
	// copying HTTP response bodies.
	BufferPool BufferPool

	// ModifyResponse is an optional function that modifies the
	// Response from the backend. It is called if the backend
	// returns a response at all, with any HTTP status code.
	// If the backend is unreachable, the optional ErrorHandler is
	// called without any call to ModifyResponse.
	//
	// If ModifyResponse returns an error, ErrorHandler is called
	// with its error value. If ErrorHandler is nil, its default
	// implementation is used.
	ModifyResponse func(*http.Response) error

	// ErrorHandler is an optional function that handles errors
	// reaching the backend or errors from ModifyResponse.
	//
	// If nil, the default is to log the provided error and return
	// a 502 Status Bad Gateway response.
	ErrorHandler func(http.ResponseWriter, *http.Request, error)
}

// A BufferPool is an interface for getting and returning temporary
// byte slices for use by io.CopyBuffer.
type BufferPool interface {
	Get() []byte
	Put([]byte)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// NewSingleHostReverseProxy returns a new ReverseProxy that routes
// URLs to the scheme, host, and base path provided in target. If the
// target's path is "/base" and the incoming request was for "/dir",
// the target request will be for /base/dir.
// NewSingleHostReverseProxy does not rewrite the Host header.
// To rewrite Host headers, use ReverseProxy directly with a custom
// Director policy.
func NewSingleHostReverseProxy(target *url.URL) *ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
	return &ReverseProxy{Director: director}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

// Hop-by-hop headers. These are removed when sent to the backend.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

func (p *ReverseProxy) defaultErrorHandler(rw http.ResponseWriter, req *http.Request, err error) {
	p.logf("http: proxy error: %v", err)
	rw.WriteHeader(http.StatusBadGateway)
}

func (p *ReverseProxy) getErrorHandler() func(http.ResponseWriter, *http.Request, error) {
	if p.ErrorHandler != nil {
		return p.ErrorHandler
	}
	return p.defaultErrorHandler
}

func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	log := logging.For("proxy/serverhttp")

	transport := p.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	ctx := req.Context()
	if cn, ok := rw.(http.CloseNotifier); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		notifyChan := cn.CloseNotify()
		go func() {
			select {
			case <-notifyChan:
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	outreq := req.WithContext(ctx) // includes shallow copies of maps, but okay
	if req.ContentLength == 0 {
		outreq.Body = nil // Issue 16036: nil Body for http.Transport retries
	}

	outreq.Header = cloneHeader(req.Header)

	p.Director(outreq)
	outreq.Close = false

	removeConnectionHeaders(outreq.Header)

	// Remove hop-by-hop headers to the backend. Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.
	for _, h := range hopHeaders {
		hv := outreq.Header.Get(h)
		if hv == "" {
			continue
		}
		if h == "Te" && hv == "trailers" {
			// Issue 21096: tell backend applications that
			// care about trailer support that we support
			// trailers. (We do, but we don't go out of
			// our way to advertise that unless the
			// incoming client request thought it was
			// worth mentioning)
			continue
		}
		outreq.Header.Del(h)
	}

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := outreq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outreq.Header.Set("X-Forwarded-For", clientIP)
	}

	res, err := transport.RoundTrip(outreq)
	if err != nil {
		p.getErrorHandler()(rw, outreq, err)
		return
	}
	isWebsocket := res.StatusCode == http.StatusSwitchingProtocols && strings.ToLower(res.Header.Get("Upgrade")) == "websocket"

	/*// Remove hop-by-hop headers listed in the
	// "Connection" header of the response.
	if c := res.Header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				res.Header.Del(f)
			}
		}
	}*/

	removeConnectionHeaders(res.Header)

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	/*if respUpdateFn != nil {
		respUpdateFn(res)
	}*/

	if isWebsocket {
		res.Body.Close()
		hj, ok := rw.(http.Hijacker)
		if !ok {
			//fmt.Errorf("Hijack error %v", rw)
			rw.WriteHeader(http.StatusBadGateway)
			log.WithField("rw", rw).Warnf("Proxy HijackRW error")
			return
		}
		log.Debugf("Hijacker RW OK")

		conn, brw, err := hj.Hijack()
		if err != nil {
			rw.WriteHeader(http.StatusBadGateway)
			log.WithError(err).Warnf("Proxy Hijack error")
			return // err
		}
		defer conn.Close()

		var backendConn net.Conn
		if hj, ok := transport.(*connHijackerTransport); ok {
			backendConn = hj.Conn
			if _, err = conn.Write(hj.Replay); err != nil {
				rw.WriteHeader(http.StatusBadGateway)
				log.WithError(err).Warnf("Proxy Hijack replay error")
				return //err
			}
			bufferPool.Put(hj.Replay)
		} else {
			if strings.EqualFold(outreq.URL.Scheme[0:5], "https") {
				tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
				log.WithField("proto", "wss").WithField("source", transport.(*customTransport).LocalAddr).WithField("host", outreq.URL.Host).Debugf("Websocket Dial")
				dialer := &net.Dialer{
					Timeout:   30 * time.Second,
					LocalAddr: transport.(*customTransport).LocalAddr,
					DualStack: true,
				}
				log.Debugf("Dialing with dialer: %+v", dialer)
				backendConn, err = tls.DialWithDialer(dialer, "tcp", outreq.URL.Host, tlsClientConfig)
			} else if strings.EqualFold(outreq.URL.Scheme[0:4], "http") {
				log.WithField("proto", "ws").WithField("source", transport.(*customTransport).LocalAddr).WithField("host", outreq.URL.Host).Debugf("Websocket Dial")
				dialer := &net.Dialer{
					Timeout:   30 * time.Second,
					LocalAddr: transport.(*customTransport).LocalAddr,
					DualStack: true,
				}
				log.Debugf("Dialing with dialer: %+v", dialer)
				backendConn, err = dialer.Dial("tcp", outreq.URL.Host)
			} else {
				log.Warnf("Unknown scheme for websocket init: %s", outreq.URL.Scheme)
				rw.WriteHeader(http.StatusBadGateway)
				return
			}
			if err != nil {
				rw.WriteHeader(http.StatusBadGateway)
				log.WithError(err).Warnf("Proxy Hijack dial error")
				return //err
			}
			outreq.Write(backendConn)
		}
		defer backendConn.Close()

		// Proxy backend -> frontend.
		go pooledIoCopy(conn, backendConn)

		// Proxy frontend -> backend.
		//
		// NOTE: Hijack() sometimes returns buffered up bytes in brw which
		// would be lost if we didn't read them out manually below.
		if brw != nil {
			if n := brw.Reader.Buffered(); n > 0 {
				rbuf, err := brw.Reader.Peek(n)
				if err != nil {
					rw.WriteHeader(http.StatusBadGateway)
					log.WithError(err).Warnf("Proxy Hijack bufferpeek error")
					return //err
				}
				backendConn.Write(rbuf)
			}
		}
		pooledIoCopy(backendConn, conn)
	} else {

		if p.ModifyResponse != nil {
			if err := p.ModifyResponse(res); err != nil {
				res.Body.Close()
				p.getErrorHandler()(rw, outreq, err)
				return
			}
		}

		copyHeader(rw.Header(), res.Header)

		// if we do not have a content Type
		// if we do have content Encoding
		// and content encoding is gzip/compress/deflate/br
		// then keep content type empty by using nil
		modheader := rw.Header()
		if len(modheader["Content-Encoding"]) > 0 && len(modheader["Content-Type"]) == 0 {
			if strings.EqualFold(modheader["Content-Encoding"][0], "gzip") ||
				strings.EqualFold(modheader["Content-Encoding"][0], "compress") ||
				strings.EqualFold(modheader["Content-Encoding"][0], "deflate") ||
				strings.EqualFold(modheader["Content-Encoding"][0], "br") {
				modheader["Content-Type"] = nil
			}
		}
		// The "Trailer" header isn't included in the Transport's response,
		// at least for *http.Transport. Build it up from Trailer.
		announcedTrailers := len(res.Trailer)
		if announcedTrailers > 0 {
			trailerKeys := make([]string, 0, len(res.Trailer))
			for k := range res.Trailer {
				trailerKeys = append(trailerKeys, k)
			}
			rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
		}

		rw.WriteHeader(res.StatusCode)
		if len(res.Trailer) > 0 {
			// Force chunking if we saw a response trailer.
			// This prevents net/http from calculating the length for short
			// bodies and adding a Content-Length.
			if fl, ok := rw.(http.Flusher); ok {
				fl.Flush()
			}
		}
		err := p.copyResponse(rw, res.Body)
		if err != nil {
			defer res.Body.Close()
			// Since we're streaming the response, if we run into an error all we can do
			// is abort the request. Issue 23643: ReverseProxy should use ErrAbortHandler
			// on read error while copying body.
			if !shouldPanicOnCopyError(req) {
				p.logf("suppressing panic for copyResponse error in test; copy error: %v", err)
				return
			}
			panic(http.ErrAbortHandler)
		}
		res.Body.Close() // close now, instead of defer, to populate res.Trailer

		if len(res.Trailer) == announcedTrailers {
			copyHeader(rw.Header(), res.Trailer)
			return
		}
		for k, vv := range res.Trailer {
			k = http.TrailerPrefix + k
			for _, v := range vv {
				rw.Header().Add(k, v)
			}
		}
	}

	return // nil
}

var inOurTests bool // whether we're in our own tests

// shouldPanicOnCopyError reports whether the reverse proxy should
// panic with http.ErrAbortHandler. This is the right thing to do by
// default, but Go 1.10 and earlier did not, so existing unit tests
// weren't expecting panics. Only panic in our own tests, or when
// running under the HTTP server.
func shouldPanicOnCopyError(req *http.Request) bool {
	if inOurTests {
		// Our tests know to handle this panic.
		return true
	}
	if req.Context().Value(http.ServerContextKey) != nil {
		// We seem to be running under an HTTP server, so
		// it'll recover the panic.
		return true
	}
	// Otherwise act like Go 1.10 and earlier to not break
	// existing tests.
	return false
}

// removeConnectionHeaders removes hop-by-hop headers listed in the "Connection" header of h.
// See RFC 7230, section 6.1
func removeConnectionHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
}

func (p *ReverseProxy) copyResponse(dst io.Writer, src io.Reader) error {
	if p.FlushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: p.FlushInterval,
				done:    make(chan bool),
			}
			go mlw.flushLoop()
			defer mlw.stop()
			dst = mlw
		}
	}

	var buf []byte
	if p.BufferPool != nil {
		buf = p.BufferPool.Get()
		defer p.BufferPool.Put(buf)
	}
	_, err := p.copyBuffer(dst, src, buf)
	return err
}

// copyBuffer returns any write errors or non-EOF read errors, and the amount
// of bytes written.
func (p *ReverseProxy) copyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if rerr != nil && rerr != io.EOF && rerr != context.Canceled {
			p.logf("httputil: ReverseProxy read error during body copy: %v", rerr)
		}
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
	}
}

func (p *ReverseProxy) logf(format string, args ...interface{}) {
	if p.ErrorLog != nil {
		p.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration

	mu   sync.Mutex // protects Write + Flush
	done chan bool
}

func (m *maxLatencyWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dst.Write(p)
}

func (m *maxLatencyWriter) flushLoop() {
	t := time.NewTicker(m.latency)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			if onExitFlushLoop != nil {
				onExitFlushLoop()
			}
			return
		case <-t.C:
			m.mu.Lock()
			m.dst.Flush()
			m.mu.Unlock()
		}
	}
}

func (m *maxLatencyWriter) stop() { m.done <- true }

// skip these headers if they already exist.
// see https://github.com/mholt/caddy/pull/1112#discussion_r80092582
var skipHeaders = map[string]struct{}{
	"Content-Type":        {},
	"Content-Disposition": {},
	"Accept-Ranges":       {},
	"Set-Cookie":          {},
	"Cache-Control":       {},
	"Expires":             {},
}

/*func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		if _, ok := dst[k]; ok {
			// skip some predefined headers
			// see https://github.com/mholt/caddy/issues/1086
			if _, shouldSkip := skipHeaders[k]; shouldSkip {
				continue
			}
			// otherwise, overwrite
			dst.Del(k)
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
*/

type respUpdateFn func(resp *http.Response)

type hijackedConn struct {
	net.Conn
	hj *connHijackerTransport
}

func (c *hijackedConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	c.hj.Replay = append(c.hj.Replay, b[:n]...)
	return
}

func (c *hijackedConn) Close() error {
	return nil
}

type connHijackerTransport struct {
	*http.Transport
	Conn   net.Conn
	Replay []byte
}

func newConnHijackerTransport(base http.RoundTripper) *connHijackerTransport {
	t := &http.Transport{
		MaxIdleConnsPerHost: -1,
	}

	if b, _ := base.(*http.Transport); b != nil {
		tlsClientConfig := b.TLSClientConfig
		if tlsClientConfig.NextProtos != nil {
			tlsClientConfig = cloneTLSClientConfig(tlsClientConfig)
			tlsClientConfig.NextProtos = nil
		}

		t.Proxy = b.Proxy
		t.TLSClientConfig = tlsClientConfig
		t.TLSHandshakeTimeout = b.TLSHandshakeTimeout
		t.Dial = b.Dial
		t.DialTLS = b.DialTLS
	} else {
		t.Proxy = http.ProxyFromEnvironment
		t.TLSHandshakeTimeout = 10 * time.Second
	}
	hj := &connHijackerTransport{t, nil, bufferPool.Get().([]byte)[:0]}

	dial := getTransportDial(t)
	dialTLS := getTransportDialTLS(t)
	t.Dial = func(network, addr string) (net.Conn, error) {
		c, err := dial(network, addr)
		hj.Conn = c
		return &hijackedConn{c, hj}, err
	}
	t.DialTLS = func(network, addr string) (net.Conn, error) {
		c, err := dialTLS(network, addr)
		hj.Conn = c
		return &hijackedConn{c, hj}, err
	}

	return hj
}

// getTransportDial always returns a plain Dialer
// and defaults to the existing t.Dial.
func getTransportDial(t *http.Transport) func(network, addr string) (net.Conn, error) {
	if t.Dial != nil {
		return t.Dial
	}
	return defaultDialer.Dial
}

// stripPort returns address without its port if it has one and
// works with IP addresses as well as hostnames formatted as host:port.
//
// IPv6 addresses (excluding the port) must be enclosed in
// square brackets similar to the requirements of Go's stdlib.
func stripPort(address string) string {
	// Keep in mind that the address might be a IPv6 address
	// and thus contain a colon, but not have a port.
	portIdx := strings.LastIndex(address, ":")
	ipv6Idx := strings.LastIndex(address, "]")
	if portIdx > ipv6Idx {
		address = address[:portIdx]
	}
	return address
}

type tlsHandshakeTimeoutError struct{}

func (tlsHandshakeTimeoutError) Timeout() bool   { return true }
func (tlsHandshakeTimeoutError) Temporary() bool { return true }
func (tlsHandshakeTimeoutError) Error() string   { return "net/http: TLS handshake timeout" }

// cloneTLSClientConfig is like cloneTLSConfig but omits
// the fields SessionTicketsDisabled and SessionTicketKey.
// This makes it safe to call cloneTLSClientConfig on a config
// in active use by a server.
func cloneTLSClientConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return &tls.Config{
		Rand:                        cfg.Rand,
		Time:                        cfg.Time,
		Certificates:                cfg.Certificates,
		NameToCertificate:           cfg.NameToCertificate,
		GetCertificate:              cfg.GetCertificate,
		RootCAs:                     cfg.RootCAs,
		NextProtos:                  cfg.NextProtos,
		ServerName:                  cfg.ServerName,
		ClientAuth:                  cfg.ClientAuth,
		ClientCAs:                   cfg.ClientCAs,
		InsecureSkipVerify:          cfg.InsecureSkipVerify,
		CipherSuites:                cfg.CipherSuites,
		PreferServerCipherSuites:    cfg.PreferServerCipherSuites,
		ClientSessionCache:          cfg.ClientSessionCache,
		MinVersion:                  cfg.MinVersion,
		MaxVersion:                  cfg.MaxVersion,
		CurvePreferences:            cfg.CurvePreferences,
		DynamicRecordSizingDisabled: cfg.DynamicRecordSizingDisabled,
		Renegotiation:               cfg.Renegotiation,
	}
}

func requestIsWebsocket(req *http.Request) bool {
	return strings.ToLower(req.Header.Get("Upgrade")) == "websocket" && strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")
}

// getTransportDial always returns a TLS Dialer
// and defaults to the existing t.DialTLS.
func getTransportDialTLS(t *http.Transport) func(network, addr string) (net.Conn, error) {
	if t.DialTLS != nil {
		return t.DialTLS
	}

	// newConnHijackerTransport will modify t.Dial after calling this method
	// => Create a backup reference.
	plainDial := getTransportDial(t)

	// The following DialTLS implementation stems from the Go stdlib and
	// is identical to what happens if DialTLS is not provided.
	// Source: https://github.com/golang/go/blob/230a376b5a67f0e9341e1fa47e670ff762213c83/src/net/http/transport.go#L1018-L1051
	return func(network, addr string) (net.Conn, error) {
		plainConn, err := plainDial(network, addr)
		if err != nil {
			return nil, err
		}

		tlsClientConfig := t.TLSClientConfig
		if tlsClientConfig == nil {
			tlsClientConfig = &tls.Config{}
		}
		if !tlsClientConfig.InsecureSkipVerify && tlsClientConfig.ServerName == "" {
			tlsClientConfig.ServerName = stripPort(addr)
		}

		tlsConn := tls.Client(plainConn, tlsClientConfig)
		errc := make(chan error, 2)
		var timer *time.Timer
		if d := t.TLSHandshakeTimeout; d != 0 {
			timer = time.AfterFunc(d, func() {
				errc <- tlsHandshakeTimeoutError{}
			})
		}
		go func() {
			err := tlsConn.Handshake()
			if timer != nil {
				timer.Stop()
			}
			errc <- err
		}()
		if err := <-errc; err != nil {
			plainConn.Close()
			return nil, err
		}
		if !tlsClientConfig.InsecureSkipVerify {
			hostname := tlsClientConfig.ServerName
			if hostname == "" {
				hostname = stripPort(addr)
			}
			if err := tlsConn.VerifyHostname(hostname); err != nil {
				plainConn.Close()
				return nil, err
			}
		}

		return tlsConn, nil
	}
}

var (
	defaultDialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	bufferPool = sync.Pool{New: createBuffer}
)

func createBuffer() interface{} {
	return make([]byte, 0, 32*1024)
}

func pooledIoCopy(dst io.Writer, src io.Reader) {
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	// CopyBuffer only uses buf up to its length and panics if it's 0.
	// Due to that we extend buf's length to its capacity here and
	// ensure it's always non-zero.
	bufCap := cap(buf)
	io.CopyBuffer(dst, src, buf[0:bufCap:bufCap])
}

// Though the relevant directive prefix is just "unix:", url.Parse
// will - assuming the regular URL scheme - add additional slashes
// as if "unix" was a request protocol.
// What we need is just the path, so if "unix:/var/run/www.socket"
// was the proxy directive, the parsed hostName would be
// "unix:///var/run/www.socket", hence the ambiguous trimming.
func socketDial(hostName string) func(network, addr string) (conn net.Conn, err error) {
	return func(network, addr string) (conn net.Conn, err error) {
		return net.Dial("unix", hostName[len("unix://"):])
	}
}
