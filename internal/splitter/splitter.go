package splitter

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const healthyFloor = 8
const downlinkTries = 4

type Upstream struct {
	ip     string
	conn   net.Conn
	reader *bufio.Reader
	born   time.Time
}

func (u *Upstream) usable(maxAge time.Duration) bool {
	return time.Since(u.born) < maxAge
}

func (u *Upstream) alive() bool {
	u.conn.SetReadDeadline(time.Now())
	var b [1]byte
	_, err := u.conn.Read(b[:])
	u.conn.SetReadDeadline(time.Time{})
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (u *Upstream) Close() { u.conn.Close() }

type Session struct {
	mu        sync.Mutex
	base      int64
	hi        int64
	delivered map[int64]bool
	moved     chan struct{}
	down      []io.Closer
	dead      bool
	seen      time.Time
	born      time.Time
}

func newSession() *Session {
	now := time.Now()
	return &Session{hi: -1, delivered: map[int64]bool{}, moved: make(chan struct{}),
		seen: now, born: now}
}

func (s *Session) wake() {
	s.mu.Lock()
	close(s.moved)
	s.moved = make(chan struct{})
	s.mu.Unlock()
}

type Splitter struct {
	cfg Config
	tls *tls.Config

	mu      sync.Mutex
	warm    []*Upstream
	takes   []time.Time
	dialing int
	fails   map[string]float64
	ips     []string
	srtt    int64 // nanoseconds, atomic

	sessMu   sync.Mutex
	sessions map[string]*Session

	stats sync.Map // string -> *int64
}

func resolvePool(cfg Config) ([]string, error) {
	if len(cfg.IPs) == 0 {
		return net.LookupHost(cfg.SNI)
	}
	return expandIPs(cfg.IPs, cfg.MaxIPs)
}

func New(cfg Config) (*Splitter, error) {
	ips, err := resolvePool(cfg)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no upstream IPs (pass -ips or fix DNS)")
	}
	tc := tlsConfig(cfg.SNI, cfg.ECH)
	fails := make(map[string]float64, len(ips))
	for _, ip := range ips {
		fails[ip] = 0
	}
	return &Splitter{
		cfg:      cfg,
		tls:      tc,
		fails:    fails,
		ips:      ips,
		srtt:     int64(300 * time.Millisecond),
		sessions: map[string]*Session{},
	}, nil
}

func tlsConfig(sni string, ech []byte) *tls.Config {
	c := &tls.Config{
		ServerName:       sni,
		NextProtos:       []string{"http/1.1"},
		CurvePreferences: []tls.CurveID{tls.X25519},
	}
	if len(ech) > 0 {
		c.EncryptedClientHelloConfigList = ech
	}
	return c
}

func (sp *Splitter) bump(key string, n int64) int64 {
	v, _ := sp.stats.LoadOrStore(key, new(int64))
	return atomic.AddInt64(v.(*int64), n)
}

func (sp *Splitter) get(key string) int64 {
	if v, ok := sp.stats.Load(key); ok {
		return atomic.LoadInt64(v.(*int64))
	}
	return 0
}

func (sp *Splitter) pickIP() string {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	total := 0.0
	weights := make([]float64, len(sp.ips))
	for i, ip := range sp.ips {
		w := math.Pow(1-sp.fails[ip], 16)
		if w < 0.001 {
			w = 0.001
		}
		weights[i] = w
		total += w
	}
	r := rand.Float64() * total
	for i, w := range weights {
		if r -= w; r <= 0 {
			return sp.ips[i]
		}
	}
	return sp.ips[len(sp.ips)-1]
}

func (sp *Splitter) score(ip string, ok bool) {
	sp.mu.Lock()
	bad := 0.0
	if !ok {
		bad = 1.0
	}
	sp.fails[ip] += 0.05 * (bad - sp.fails[ip])
	sp.mu.Unlock()
}

func (sp *Splitter) hedgeAfter() time.Duration {
	d := time.Duration(5 * atomic.LoadInt64(&sp.srtt))
	if d < sp.cfg.HedgeMin {
		return sp.cfg.HedgeMin
	}
	if d > sp.cfg.HedgeMax {
		return sp.cfg.HedgeMax
	}
	return d
}

func (sp *Splitter) updateRTT(d time.Duration) {
	old := atomic.LoadInt64(&sp.srtt)
	atomic.StoreInt64(&sp.srtt, old+int64(0.1*float64(int64(d)-old)))
}

func (sp *Splitter) dial() (*Upstream, error) {
	ip := sp.pickIP()
	d := net.Dialer{Timeout: sp.cfg.DialTimeout}
	addr := net.JoinHostPort(ip, strconv.Itoa(sp.cfg.UpstreamPort))
	raw, err := d.Dial("tcp", addr)
	if err == nil {
		conn := tls.Client(raw, sp.tls)
		raw.SetDeadline(time.Now().Add(sp.cfg.DialTimeout))
		err = conn.Handshake()
		if err == nil {
			raw.SetDeadline(time.Time{})
			return &Upstream{ip: ip, conn: conn, reader: bufio.NewReader(conn), born: time.Now()}, nil
		}
		conn.Close()
	}
	var echErr *tls.ECHRejectionError
	if errors.As(err, &echErr) {
		echWarn.Do(func() {
			log.Print("ECH rejected by the edge; the config may be stale or ECH is not available here")
		})
	}
	sp.score(ip, false)
	sp.bump("dials failed", 1)
	return nil, err
}

var echWarn sync.Once

func (sp *Splitter) keepWarm() {
	for {
		now := time.Now()
		sp.mu.Lock()
		for len(sp.takes) > 0 && now.Sub(sp.takes[0]) > time.Second {
			sp.takes = sp.takes[1:]
		}
		for len(sp.warm) > 0 && !sp.warm[0].usable(sp.cfg.WarmMaxAge) {
			sp.warm[0].Close()
			sp.warm = sp.warm[1:]
		}
		target := sp.cfg.WarmMin + len(sp.takes)/3
		if target > sp.cfg.WarmMax {
			target = sp.cfg.WarmMax
		}
		for len(sp.warm)+sp.dialing < target {
			sp.dialing++
			go func() {
				u, err := sp.dial()
				sp.mu.Lock()
				sp.dialing--
				if err == nil {
					sp.warm = append(sp.warm, u)
				}
				sp.mu.Unlock()
				if err != nil {
					time.Sleep(time.Second)
				}
			}()
		}
		sp.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
}

func (sp *Splitter) take() (*Upstream, error) {
	sp.mu.Lock()
	sp.takes = append(sp.takes, time.Now())
	for len(sp.warm) > 0 {
		u := sp.warm[0]
		sp.warm = sp.warm[1:]
		sp.mu.Unlock()
		if u.usable(sp.cfg.WarmMaxAge) && u.alive() {
			return u, nil
		}
		u.Close()
		sp.mu.Lock()
	}
	sp.mu.Unlock()
	return sp.dial()
}

func (sp *Splitter) getSession(sid string) *Session {
	sp.sessMu.Lock()
	defer sp.sessMu.Unlock()
	s := sp.sessions[sid]
	if s == nil {
		s = newSession()
		sp.sessions[sid] = s
	}
	s.seen = time.Now()
	return s
}

func (sp *Splitter) kill(s *Session) {
	s.mu.Lock()
	if !s.dead {
		sp.bump("sessions lost", 1)
	}
	s.dead = true
	down := s.down
	s.mu.Unlock()
	for _, w := range down {
		w.Close()
	}
	s.wake()
}

func (sp *Splitter) postOnce(req []byte) error {
	u, err := sp.take()
	if err != nil {
		return err
	}
	defer u.Close()
	start := time.Now()
	u.conn.SetDeadline(time.Now().Add(sp.cfg.CopyTimeout))
	if _, err := u.conn.Write(req); err != nil {
		sp.score(u.ip, false)
		return err
	}
	resp, err := readResponse(u.reader)
	if err != nil {
		sp.score(u.ip, false)
		return err
	}
	sp.score(u.ip, true)
	sp.updateRTT(time.Since(start))
	if code := statusCode(resp); code != "200" {
		sp.bump("http "+code, 1)
		return errors.New(firstLine(resp))
	}
	return nil
}

func (sp *Splitter) post(req []byte) bool {
	results := make(chan error, 2*sp.cfg.Copies+4)
	inflight := 0
	sp.bump("posts", 1)
	launch := func() {
		inflight++
		sp.bump("copies", 1)
		go func() { results <- sp.postOnce(req) }()
	}
	overall := time.NewTimer(sp.cfg.PostTimeout)
	defer overall.Stop()
	hedge := time.NewTimer(sp.hedgeAfter())
	defer hedge.Stop()
	launch()
	for {
		select {
		case err := <-results:
			inflight--
			if err == nil {
				return true
			}
			if inflight < sp.cfg.Copies {
				launch()
			}
		case <-hedge.C:
			if inflight < sp.cfg.Copies {
				launch()
			}
			hedge.Reset(sp.hedgeAfter())
		case <-overall.C:
			return false
		}
	}
}

func (sp *Splitter) deliver(s *Session, seq int64, req []byte) {
	if !sp.post(req) {
		sp.kill(s)
		return
	}
	s.mu.Lock()
	s.delivered[seq] = true
	for s.delivered[s.base] {
		delete(s.delivered, s.base)
		s.base++
	}
	s.mu.Unlock()
	s.wake()
}

func pump(dst io.WriteCloser, src io.Reader) {
	io.Copy(dst, src)
	dst.Close()
}

func (sp *Splitter) download(s *Session, req []byte, cr io.Reader, cw io.WriteCloser) {
	for attempt := 0; attempt < downlinkTries; attempt++ {
		u, err := sp.take()
		if err != nil {
			continue
		}
		u.conn.SetWriteDeadline(time.Now().Add(sp.cfg.GetTimeout))
		if _, err := u.conn.Write(req); err != nil {
			u.Close()
			sp.score(u.ip, false)
			continue
		}
		u.conn.SetReadDeadline(time.Now().Add(sp.cfg.GetTimeout))
		head, err := readHead(u.reader)
		if err != nil {
			u.Close()
			sp.score(u.ip, false)
			continue
		}
		u.conn.SetDeadline(time.Time{})
		sp.score(u.ip, true)

		s.mu.Lock()
		s.down = []io.Closer{cw, u.conn}
		s.mu.Unlock()

		cw.Write(forceClose(head))
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); pump(cw, u.reader) }()
		go func() { defer wg.Done(); pump(u.conn, cr) }()
		wg.Wait()

		s.mu.Lock()
		if !s.dead && s.hi >= s.base {
			log.Printf("downlink closed by server, %d posts pending at seq %d", s.hi-s.base+1, s.base)
		}
		s.down, s.dead = nil, true
		s.mu.Unlock()
		s.wake()
		return
	}
	sp.kill(s)
}

func (sp *Splitter) handle(client net.Conn) {
	defer client.Close()
	cr := bufio.NewReader(client)
	for {
		head, err := readHead(cr)
		if err != nil {
			return
		}
		req := trim(head)
		if n, ok := headerValue(head, "content-length"); ok {
			length, err := strconv.Atoi(n)
			if err != nil {
				return
			}
			body := make([]byte, length)
			if _, err := io.ReadFull(cr, body); err != nil {
				return
			}
			req = append(req, body...)
		}

		target := requestTarget(head)
		seg := splitPath(target)
		if !isPost(head) {
			sid := lastSeg(seg)
			sp.download(sp.getSession(sid), req, cr, client)
			return
		}

		client.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		sid, seq, ok := sessionSeq(seg)
		if !ok {
			go sp.post(req)
			continue
		}
		s := sp.getSession(sid)
		sp.windowGate(s, seq, req)
	}
}

func (sp *Splitter) windowGate(s *Session, seq int64, req []byte) {
	s.mu.Lock()
	if seq > s.hi {
		s.hi = seq
	}
	s.mu.Unlock()
	deadline := time.Now().Add(sp.cfg.StallTimeout)
	for {
		s.mu.Lock()
		ch, blocked, dead, base := s.moved, seq >= s.base+sp.cfg.Window && !s.dead, s.dead, s.base
		s.mu.Unlock()
		if dead || seq < base {
			return
		}
		if !blocked {
			break
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			sp.kill(s)
			return
		}
		select {
		case <-ch:
		case <-time.After(rem):
		}
	}
	go sp.deliver(s, seq, req)
}

func (sp *Splitter) reaper() {
	var last int64 = -1
	for {
		time.Sleep(15 * time.Second)
		now := time.Now()
		sp.sessMu.Lock()
		for sid, s := range sp.sessions {
			s.mu.Lock()
			idle := s.down == nil && now.Sub(s.seen) > time.Minute
			s.mu.Unlock()
			if idle {
				delete(sp.sessions, sid)
			}
		}
		sp.sessMu.Unlock()
		posts, lost := sp.get("posts"), sp.get("sessions lost")
		if posts+lost == last {
			continue // nothing happened since the last line
		}
		last = posts + lost
		pool, good := sp.poolHealth()
		log.Printf("posts %d resent %d lost %d | rtt %dms | ips %d/%d clean",
			posts, sp.get("copies")-posts, lost,
			atomic.LoadInt64(&sp.srtt)/int64(time.Millisecond), good, pool)
	}
}

func (sp *Splitter) poolHealth() (pool, good int) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	for _, f := range sp.fails {
		if f < 0.15 {
			good++
		}
	}
	return len(sp.fails), good
}

func (sp *Splitter) setIPs(ips []string) {
	fails := make(map[string]float64, len(ips))
	for _, ip := range ips {
		fails[ip] = 0
	}
	sp.mu.Lock()
	sp.ips, sp.fails = ips, fails
	sp.mu.Unlock()
}

func (sp *Splitter) initialSeed() {
	sp.mu.Lock()
	cur := append([]string(nil), sp.ips...)
	sp.mu.Unlock()
	if len(cur) <= 16 {
		return
	}
	if fresh := seedIPs(sp.tls, cur, sp.cfg.SNI, sp.cfg.UpstreamPort); len(fresh) >= seedMinGood {
		sp.setIPs(fresh)
	}
}

func (sp *Splitter) refresher() {
	for {
		time.Sleep(time.Minute)
		if _, good := sp.poolHealth(); good >= healthyFloor {
			continue
		}
		cands, err := resolvePool(sp.cfg)
		if err != nil || len(cands) <= 16 {
			continue
		}
		if fresh := seedIPs(sp.tls, cands, sp.cfg.SNI, sp.cfg.UpstreamPort); len(fresh) >= seedMinGood {
			sp.setIPs(fresh)
		}
	}
}

func (sp *Splitter) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", sp.cfg.Listen)
	if err != nil {
		return err
	}
	go sp.keepWarm()
	go sp.reaper()
	go sp.initialSeed()
	go sp.refresher()
	log.Printf("listening on %s -> %s (%d IPs, probing)", sp.cfg.Listen, sp.cfg.SNI, len(sp.ips))
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go sp.handle(conn)
	}
}
