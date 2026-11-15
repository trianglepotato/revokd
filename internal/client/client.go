// Package client is a minimal VPN client used by the demo and tests.
package client

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// DeniedError is returned when the gateway refuses the session.
type DeniedError struct{ Reason string }

func (e *DeniedError) Error() string { return "denied: " + e.Reason }

// Dial opens a session through a gateway and asks the upstream to stream at
// rate bytes/sec. The returned reader yields upstream data.
func Dial(gw, session, token string, rate int64) (net.Conn, io.Reader, error) {
	c, err := net.DialTimeout("tcp", gw, 2*time.Second)
	if err != nil {
		return nil, nil, err
	}
	if _, werr := fmt.Fprintf(c, "HELLO %s %s\n", session, token); werr != nil {
		c.Close()
		return nil, nil, werr
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	_ = c.SetReadDeadline(time.Time{})
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "DENY ") {
		c.Close()
		return nil, nil, &DeniedError{Reason: strings.TrimPrefix(line, "DENY ")}
	}
	if line != "OK" {
		c.Close()
		return nil, nil, errors.New("unexpected handshake: " + line)
	}
	if _, err := fmt.Fprintf(c, "RATE %d\n", rate); err != nil {
		c.Close()
		return nil, nil, err
	}
	return c, r, nil
}

// Result describes one download.
type Result struct {
	Total       int64
	CrossedAt   time.Time // when Total first reached the watch mark (zero if never)
	ClosedAt    time.Time
	CutByRemote bool
}

// Drain reads until the connection ends or maxBytes / deadline is reached.
func Drain(c net.Conn, r io.Reader, watch, maxBytes int64, deadline time.Duration) Result {
	var res Result
	buf := make([]byte, 32*1024)
	_ = c.SetReadDeadline(time.Now().Add(deadline))
	for {
		n, err := r.Read(buf)
		res.Total += int64(n)
		if watch > 0 && res.CrossedAt.IsZero() && res.Total >= watch {
			res.CrossedAt = time.Now()
		}
		if maxBytes > 0 && res.Total >= maxBytes {
			res.ClosedAt = time.Now()
			c.Close()
			return res
		}
		if err != nil {
			res.ClosedAt = time.Now()
			var ne net.Error
			res.CutByRemote = !errors.As(err, &ne) || !ne.Timeout()
			c.Close()
			return res
		}
	}
}
