package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/freedomproto/xhttp-splitter/internal/splitter"
)

const repoURL = "https://github.com/freedomproto/xhttp-splitter"

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) > 1 && os.Args[1] == "scan" {
		runScan(os.Args[2:])
		return
	}

	cfg := splitter.DefaultConfig()
	fs := flag.NewFlagSet("xhttp-splitter", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "xhttp-splitter %s — %s\n\n", version, repoURL)
		fmt.Fprintf(os.Stderr, "Usage of xhttp-splitter:\n")
		fs.PrintDefaults()
	}
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.StringVar(&cfg.SNI, "sni", cfg.SNI, "edge domain (TLS SNI + default Host) [env XHTTP_SNI]")
	ips := fs.String("ips", "", "IPs or CIDR ranges serving the SNI, comma/space separated; empty = DNS [env XHTTP_IPS]")
	ech := fs.String("ech", os.Getenv("XHTTP_ECH"), "hide the SNI with ECH: 'auto' (HTTPS DNS record), 'dns:HOST:PORT', an http(s) URL, or base64 [env XHTTP_ECH]")
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "listen address host:port [env XHTTP_LISTEN]")
	fs.IntVar(&cfg.UpstreamPort, "upstream-port", cfg.UpstreamPort, "edge TLS port")
	fs.IntVar(&cfg.MaxIPs, "max-ips", cfg.MaxIPs, "cap on IPs drawn from the given ranges")
	win := fs.Int("window", int(cfg.Window), "seqs allowed ahead of the oldest undelivered (keep < server scMaxBufferedPosts)")
	fs.IntVar(&cfg.Copies, "copies", cfg.Copies, "max concurrent attempts per request")
	fs.IntVar(&cfg.WarmMin, "warm-min", cfg.WarmMin, "idle pre-dialed connections kept ready")
	fs.IntVar(&cfg.WarmMax, "warm-max", cfg.WarmMax, "upper bound on the warm pool under load")
	fs.DurationVar(&cfg.CopyTimeout, "copy-timeout", cfg.CopyTimeout, "abandon+replace a copy with no answer after this")
	fs.DurationVar(&cfg.PostTimeout, "post-timeout", cfg.PostTimeout, "give up a request (tear the session down) after this")
	fs.DurationVar(&cfg.StallTimeout, "stall-timeout", cfg.StallTimeout, "tear down a session whose window stays full this long")
	fs.Parse(os.Args[1:])
	if *showVersion {
		fmt.Printf("xhttp-splitter %s\n%s\n", version, repoURL)
		return
	}

	cfg.Window = int64(*win)
	if *ips != "" {
		cfg.IPs = splitter.SplitList(*ips)
	}
	if cfg.SNI == "" {
		fmt.Fprintln(os.Stderr, "error: -sni (or XHTTP_SNI) is required")
		fs.Usage()
		os.Exit(2)
	}
	if *ech != "" {
		b, err := loadECH(*ech, cfg.SNI)
		if err != nil {
			log.Fatalf("ech: %v", err)
		}
		cfg.ECH = b
		log.Printf("ECH enabled (%d-byte config), SNI hidden", len(b))
	}

	sp, err := splitter.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := sp.Serve(ctx); err != nil {
		log.Fatal(err)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	sni := fs.String("sni", os.Getenv("XHTTP_SNI"), "edge domain to probe [env XHTTP_SNI]")
	count := fs.Int("count", 500, "max random IPs to probe before giving up")
	need := fs.Int("need", 10, "stop once this many clean IPs are found")
	tries := fs.Int("tries", 3, "probes an IP must all pass to count as clean")
	port := fs.Int("upstream-port", 443, "edge TLS port")
	ech := fs.String("ech", "", "probe with ECH too: 'auto', 'dns:HOST:PORT', an http(s) URL, or base64")
	var ranges multiFlag
	fs.Var(&ranges, "range", "CIDR to sample (repeatable, required)")
	fs.Parse(args)
	if *sni == "" {
		log.Fatal("scan: -sni (or XHTTP_SNI) is required")
	}
	if len(ranges) == 0 {
		log.Fatal("scan: at least one -range CIDR is required (e.g. -range 104.16.0.0/13)")
	}
	var echBytes []byte
	if *ech != "" {
		b, err := loadECH(*ech, *sni)
		if err != nil {
			log.Fatalf("ech: %v", err)
		}
		echBytes = b
	}
	splitter.RunScan(*sni, ranges, *count, *port, *tries, *need, echBytes)
}

// loadECH returns an ECHConfigList from one of:
//   - "auto"            fetch the HTTPS DNS record of sni via 1.1.1.1
//   - "dns:HOST:PORT"   fetch it via the given resolver
//   - "http(s)://..."   fetch it from a URL
//   - base64            the config list itself
func loadECH(value, sni string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "auto" {
		return splitter.FetchECH(sni, "1.1.1.1:53")
	}
	if r, ok := strings.CutPrefix(value, "dns:"); ok {
		return splitter.FetchECH(sni, r)
	}
	raw := []byte(value)
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Get(value)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch %s: %s", value, resp.Status)
		}
		if raw, err = io.ReadAll(io.LimitReader(resp.Body, 1<<16)); err != nil {
			return nil, err
		}
	}
	s := strings.TrimSpace(string(raw))
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty ECH config")
	}
	return raw, nil
}

type multiFlag []string

func (m *multiFlag) String() string { return fmt.Sprint([]string(*m)) }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
