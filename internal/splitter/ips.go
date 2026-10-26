package splitter

import (
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
)

func expandIPs(entries []string, max int) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(ip string) {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	for _, e := range entries {
		if !strings.Contains(e, "/") {
			if _, err := netip.ParseAddr(e); err != nil {
				return nil, fmt.Errorf("bad IP %q: %w", e, err)
			}
			add(e)
			continue
		}
		p, err := netip.ParsePrefix(e)
		if err != nil {
			return nil, fmt.Errorf("bad range %q: %w", e, err)
		}
		p = p.Masked()
		hostBits := p.Addr().BitLen() - p.Bits()
		if hostBits <= 20 && 1<<hostBits <= max {
			for a := p.Addr(); p.Contains(a); a = a.Next() {
				add(a.String())
			}
		} else {
			for i := 0; i < max; i++ {
				add(randomInPrefix(p).String())
			}
		}
	}
	return out, nil
}

func randomInPrefix(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		if rand.Intn(2) == 1 {
			b[i/8] |= 1 << (7 - i%8)
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
