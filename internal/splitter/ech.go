package splitter

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"strings"
	"time"
)

func FetchECH(name, resolver string) ([]byte, error) {
	c, err := net.DialTimeout("udp", resolver, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(buildHTTPSQuery(name)); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseECHAnswer(buf[:n])
}

func buildHTTPSQuery(name string) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:], uint16(rand.Intn(65536)))
	binary.BigEndian.PutUint16(hdr[2:], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(hdr[4:], 1)      // one question
	binary.BigEndian.PutUint16(hdr[10:], 1)     // one additional (EDNS0 OPT)
	b := hdr
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)                                   // root label
	b = append(b, 0, 65, 0, 1)                         // QTYPE=HTTPS(65), QCLASS=IN
	b = append(b, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0) // OPT RR, 4096-byte UDP buffer
	return b
}

func parseECHAnswer(msg []byte) ([]byte, error) {
	if len(msg) < 12 {
		return nil, errors.New("short DNS response")
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		off = skipName(msg, off) + 4
	}
	for i := 0; i < an && off+10 <= len(msg); i++ {
		off = skipName(msg, off)
		if off+10 > len(msg) {
			break
		}
		typ := binary.BigEndian.Uint16(msg[off:])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		rd := off + 10
		if rd+rdlen > len(msg) {
			break
		}
		if typ == 65 {
			if ech := echSvcParam(msg[rd : rd+rdlen]); ech != nil {
				return ech, nil
			}
		}
		off = rd + rdlen
	}
	return nil, errors.New("no ECH in the HTTPS record (ECH may be disabled for this domain)")
}

func echSvcParam(rd []byte) []byte {
	p := skipName(rd, 2) // skip 2-byte priority, then the target name
	for p+4 <= len(rd) {
		key := binary.BigEndian.Uint16(rd[p:])
		l := int(binary.BigEndian.Uint16(rd[p+2:]))
		v := p + 4
		if v+l > len(rd) {
			return nil
		}
		if key == 5 {
			out := make([]byte, l)
			copy(out, rd[v:v+l])
			return out
		}
		p = v + l
	}
	return nil
}

func skipName(msg []byte, off int) int {
	for off < len(msg) {
		b := int(msg[off])
		if b == 0 {
			return off + 1
		}
		if b&0xc0 == 0xc0 {
			return off + 2
		}
		off += b + 1
	}
	return off
}
