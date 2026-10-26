package splitter

import (
	"os"
	"strings"
	"time"
)

type Config struct {
	SNI          string
	IPs          []string
	ECH          []byte
	MaxIPs       int
	Listen       string
	UpstreamPort int
	Window       int64
	Copies       int
	WarmMin      int
	WarmMax      int
	WarmMaxAge   time.Duration
	DialTimeout  time.Duration
	HedgeMin     time.Duration
	HedgeMax     time.Duration
	CopyTimeout  time.Duration
	PostTimeout  time.Duration
	GetTimeout   time.Duration
	StallTimeout time.Duration
}

func DefaultConfig() Config {
	return Config{
		Listen:       env("XHTTP_LISTEN", "127.0.0.1:10443"),
		SNI:          os.Getenv("XHTTP_SNI"),
		IPs:          SplitList(os.Getenv("XHTTP_IPS")),
		MaxIPs:       256,
		UpstreamPort: 443,
		Window:       12,
		Copies:       2,
		WarmMin:      8,
		WarmMax:      64,
		WarmMaxAge:   20 * time.Second,
		DialTimeout:  8 * time.Second,
		HedgeMin:     500 * time.Millisecond,
		HedgeMax:     1500 * time.Millisecond,
		CopyTimeout:  3 * time.Second,
		PostTimeout:  20 * time.Second,
		GetTimeout:   3 * time.Second,
		StallTimeout: 24 * time.Second,
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func SplitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
