package splitter

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	seedProbeMax = 150
	seedKeep     = 32
	seedMinGood  = 4
)

func seedIPs(tc *tls.Config, ips []string, sni string, port int) []string {
	probe := append([]string(nil), ips...)
	mrand.Shuffle(len(probe), func(i, j int) { probe[i], probe[j] = probe[j], probe[i] })
	if len(probe) > seedProbeMax {
		probe = probe[:seedProbeMax]
	}
	log.Printf("probing %d edge IPs...", len(probe))
	results := make([]scanResult, len(probe))
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	for i, ip := range probe {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = probeIP(tc, ip, sni, port, 1, 3*time.Second, false)
		}(i, ip)
	}
	wg.Wait()
	sort.Slice(results, func(a, b int) bool {
		if results[a].ok != results[b].ok {
			return results[a].ok > results[b].ok
		}
		return results[a].median < results[b].median
	})
	var good []string
	for _, r := range results {
		if r.ok > 0 {
			good = append(good, r.ip)
		}
	}
	if len(good) < seedMinGood {
		log.Printf("only %d IPs answered; keeping the full pool", len(good))
		return ips
	}
	if len(good) > seedKeep {
		good = good[:seedKeep]
	}
	log.Printf("selected %d reachable IPs", len(good))
	return good
}

type scanResult struct {
	ip     string
	ok     int
	median time.Duration
}

func RunScan(sni string, ranges []string, count, port, tries, need int, ech []byte) {
	tc := tlsConfig(sni, ech)
	ips := sampleRanges(ranges, max(count, need))
	fmt.Printf("probing up to %d IPs, need %d clean (Ctrl+C to stop early)\n\n", len(ips), need)

	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var found []string
	var enough int32
	for _, ip := range ips {
		if atomic.LoadInt32(&enough) == 1 {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			if atomic.LoadInt32(&enough) == 1 {
				return
			}
			r := probeIP(tc, ip, sni, port, tries, 4*time.Second, true)
			if r.ok < tries {
				return
			}
			mu.Lock()
			found = append(found, ip)
			n := len(found)
			mu.Unlock()
			fmt.Printf("%-16s %dms\n", ip, r.median.Milliseconds())
			if n >= need {
				atomic.StoreInt32(&enough, 1)
			}
		}(ip)
	}
	wg.Wait()

	if len(found) == 0 {
		fmt.Println("\nno clean IPs found; widen -count or try other -range values")
		return
	}
	fmt.Printf("\nclean IPs: %s\n", join(found))
}

func probeIP(tc *tls.Config, ip, sni string, port, tries int, timeout time.Duration, failFast bool) scanResult {
	var times []time.Duration
	for i := 0; i < tries; i++ {
		if t, ok := probeOnce(tc, ip, sni, port, timeout); ok {
			times = append(times, t)
		} else if failFast {
			break
		}
	}
	r := scanResult{ip: ip, ok: len(times)}
	if len(times) > 0 {
		sort.Slice(times, func(a, b int) bool { return times[a] < times[b] })
		r.median = times[len(times)/2]
	}
	return r
}

func probeOnce(tc *tls.Config, ip, sni string, port int, timeout time.Duration) (time.Duration, bool) {
	payload := make([]byte, 3500)
	rand.Read(payload)
	req := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", sni, len(payload))
	d := net.Dialer{Timeout: timeout}
	raw, err := d.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return 0, false
	}
	defer raw.Close()
	conn := tls.Client(raw, tc)
	conn.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	if conn.Handshake() != nil {
		return 0, false
	}
	if _, err := conn.Write(append([]byte(req), payload...)); err != nil {
		return 0, false
	}
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		return 0, false
	}
	return time.Since(start), true
}

func sampleRanges(ranges []string, count int) []string {
	var prefixes []netip.Prefix
	for _, c := range ranges {
		if p, err := netip.ParsePrefix(c); err == nil {
			prefixes = append(prefixes, p.Masked())
		}
	}
	seen := map[string]bool{}
	var out []string
	for len(out) < count && len(prefixes) > 0 {
		p := prefixes[mrand.Intn(len(prefixes))]
		ip := randomInPrefix(p).String()
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}
