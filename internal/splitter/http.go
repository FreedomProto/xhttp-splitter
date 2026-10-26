package splitter

import (
	"bufio"
	"bytes"
	"io"
	"strconv"
)

var dropHeaders = map[string]bool{
	"sec-ch-ua": true, "sec-ch-ua-mobile": true, "sec-ch-ua-platform": true,
	"sec-fetch-dest": true, "sec-fetch-mode": true, "sec-fetch-site": true,
	"dnt": true, "pragma": true, "priority": true, "accept-language": true,
	"cache-control": true, "accept-encoding": true,
}

func readHead(r *bufio.Reader) ([]byte, error) {
	var head []byte
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		head = append(head, line...)
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			return head, nil
		}
		if len(head) > 1<<16 {
			return nil, io.ErrShortBuffer
		}
	}
}

func headerValue(head []byte, name string) (string, bool) {
	for _, line := range bytes.Split(head, []byte("\r\n"))[1:] {
		k, v, ok := bytes.Cut(line, []byte(":"))
		if ok && string(bytes.ToLower(bytes.TrimSpace(k))) == name {
			return string(bytes.TrimSpace(v)), true
		}
	}
	return "", false
}

func trim(head []byte) []byte {
	lines := bytes.Split(head, []byte("\r\n"))
	out := [][]byte{lines[0]}
	for _, line := range lines[1 : len(lines)-2] {
		k, _, _ := bytes.Cut(line, []byte(":"))
		if !dropHeaders[string(bytes.ToLower(bytes.TrimSpace(k)))] {
			out = append(out, line)
		}
	}
	return append(bytes.Join(out, []byte("\r\n")), []byte("\r\n\r\n")...)
}

func forceClose(head []byte) []byte {
	lines := bytes.Split(head, []byte("\r\n"))
	out := make([][]byte, 0, len(lines))
	for _, line := range lines[:len(lines)-2] {
		if !bytes.HasPrefix(bytes.ToLower(line), []byte("connection:")) {
			out = append(out, line)
		}
	}
	out = append(out, []byte("Connection: close"), nil, nil)
	return bytes.Join(out, []byte("\r\n"))
}

func readResponse(r *bufio.Reader) ([]byte, error) {
	head, err := readHead(r)
	if err != nil {
		return nil, err
	}
	if n, ok := headerValue(head, "content-length"); ok {
		length, err := strconv.Atoi(n)
		if err != nil {
			return nil, err
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		return append(head, body...), nil
	}
	if te, ok := headerValue(head, "transfer-encoding"); ok && te == "chunked" {
		body, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		return append(head, body...), nil
	}
	return head, nil
}

func isPost(head []byte) bool {
	return bytes.HasPrefix(head, []byte("POST "))
}

func requestTarget(head []byte) []byte {
	parts := bytes.SplitN(head, []byte(" "), 3)
	if len(parts) < 2 {
		return nil
	}
	target, _, _ := bytes.Cut(parts[1], []byte("?"))
	return target
}

func splitPath(target []byte) [][]byte {
	return bytes.Split(target, []byte("/"))
}

func lastSeg(seg [][]byte) string {
	if len(seg) == 0 {
		return ""
	}
	return string(seg[len(seg)-1])
}

func sessionSeq(seg [][]byte) (string, int64, bool) {
	if len(seg) < 2 {
		return "", 0, false
	}
	seq, err := strconv.ParseInt(string(seg[len(seg)-1]), 10, 64)
	if err != nil {
		return "", 0, false
	}
	return string(seg[len(seg)-2]), seq, true
}

func statusCode(resp []byte) string {
	parts := bytes.SplitN(resp, []byte(" "), 3)
	if len(parts) >= 2 {
		return string(parts[1])
	}
	return ""
}

func firstLine(resp []byte) string {
	if i := bytes.Index(resp, []byte("\r\n")); i >= 0 {
		return string(resp[:i])
	}
	return string(resp)
}
