# xhttp-splitter

*[فارسی](README.fa.md)*

A local proxy that keeps an **Xray `xhttp` (packet-up) tunnel** alive where a DPI throttles
TLS connections by SNI. Each HTTP/1.1 request from Xray leaves on its own single-use TLS
connection, so no connection ever uploads enough — or carries a second request — to be
throttled.

```
xray (xhttp, security:none) → xhttp-splitter → one request per TLS conn → edge IPs → server
```

Edge-agnostic: it needs only an SNI and the IPs (or CIDR ranges) that serve it.

## The problem

Some DPIs let a TLS connection open, then blackhole it once the client uploads more than a
few KB or sends a second request on it; downloads are unaffected. Xray reuses its upload
connections, so an `xhttp` tunnel stalls within seconds — uploads first. xhttp-splitter
spreads each request onto a fresh connection, keeps a warm pool so a POST costs one round
trip, retries a stuck request elsewhere, and steers traffic to the edge IPs that are still
clean.

## Compatibility

Specific transport, any inner protocol. Only `xhttp` **packet-up** applies: that mode splits
the upload into independent, sequence-numbered requests the server reassembles, which is what
lets each ride its own connection. A `ws`/`grpc`/`raw` tunnel is one continuous stream and
cannot be split.

| Xray setting | |
|---|---|
| VLESS / VMess / Trojan / Shadowsocks inner protocol | ✅ relayed as raw HTTP/1.1 |
| `xhttp` transport, mode `packet-up` (or `auto`) | ✅ |
| session & seq in path, data in body (defaults) | ✅ |
| download leg (`stream-down` GET) | ✅ |
| `ws` / `grpc` / `httpupgrade` / `raw` | ❌ not a packet tunnel |
| `xhttp` mode `stream-up` / `stream-one` | ❌ single long upload |
| session/seq in query, header, or cookie | ❌ path only |

Matching client config: [`examples/xray-client.example.json`](examples/xray-client.example.json)
— `security: none` (the splitter adds TLS), outbound pointing at the splitter.

## Build & run

```
go build -o xhttp-splitter .        # static binary, no dependencies (Go 1.23+)

xhttp-splitter -sni cloudflare.com -ips 104.16.0.0/13,172.64.0.0/13
```

Then point Xray's `xhttp` outbound at `127.0.0.1:10443` with `security: none`. Small ranges
are enumerated, large ones sampled; with no `-ips` the SNI is resolved over DNS. At startup
the pool is probed in the background, trimmed to the clean IPs, and re-probed when too few
stay clean.

| Flag | Env | Default | |
|---|---|---|---|
| `-sni` | `XHTTP_SNI` | required | edge domain (TLS SNI + default Host) |
| `-ips` | `XHTTP_IPS` | DNS of `-sni` | IPs / CIDR ranges serving the SNI |
| `-ech` | `XHTTP_ECH` | off | hide the SNI: `auto`, `dns:HOST:PORT`, a URL, or base64 |
| `-listen` | `XHTTP_LISTEN` | `127.0.0.1:10443` | local listen address |
| `-window` | | `12` | seqs in flight; keep below the server's `scMaxBufferedPosts` |
| `-copies` | | `2` | max concurrent attempts per request |
| `-post-timeout` | | `20s` | give up a request (tears the session down) |

`-h` lists the rest.

## Finding clean IPs

Recommended: just hand a range to `-ips` and let the splitter manage it — it probes the
range, keeps the clean IPs, and re-probes as they burn out, with no manual step. Use `scan`
only to discover a fixed set to pin: it probes random IPs from the ranges and prints the
clean ones as it finds them, stopping once it has enough (`-need`, default 10):

```
xhttp-splitter scan -sni cloudflare.com -range 104.16.0.0/13 -range 172.64.0.0/13
```

## Hiding the SNI (ECH)

With Encrypted Client Hello the real SNI is encrypted inside the ClientHello; the DPI sees
only the config's public name.

```
xhttp-splitter -sni cloudflare.com -ips 104.16.0.0/13 -ech auto
```

`-ech` takes `auto` (read the domain's HTTPS DNS record via 1.1.1.1 — recommended),
`dns:HOST:PORT`, an http(s) URL, or a base64 ECHConfigList. It fails closed if the edge
rejects ECH, so a working tunnel with `-ech` set means ECH is really in effect. Self-test
against Cloudflare's ECH endpoint, which then reports `sni=encrypted`:

```
xhttp-splitter -sni crypto.cloudflare.com -ips 162.159.135.79,162.159.136.79 -ech auto
```

Not every network allows ECH: some DPIs blackhole any ClientHello that carries the ECH
extension, even when the DNS fetch succeeds. ECH is independent of the request-splitting,
so test it on your own link before relying on it.

## Docker

```
docker build -t xhttp-splitter .
docker run --rm -p 10443:10443 -e XHTTP_SNI=cloudflare.com -e XHTTP_IPS=104.16.0.0/13 xhttp-splitter
```

~6 MB `scratch` image, listening on `0.0.0.0:10443` inside the container.

## How it works

- **One request per connection** — each POST/GET gets a fresh TLS connection, closed right after.
- **Warm pool** — connections are pre-dialed and sized to the request rate; dead ones are never handed out.
- **Ordered window** — a small window of sequence numbers is in flight, tracked so the server's reorder buffer never overflows.
- **Hedge & replace** — a request the edge accepts but does not answer is resent elsewhere and the stuck connection dropped.
- **Probe, score & refresh** — IPs are scored live and the pool is re-probed from the ranges as they burn out.

## Support

If this project helps you, you can donate — see [DONATE.md](DONATE.md).

## License

MIT — see [LICENSE](LICENSE).

---

[Telegram @FreedomProto](https://t.me/FreedomProto)
