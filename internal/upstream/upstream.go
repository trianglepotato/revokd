// Package upstream is a stand-in for a protected internal resource (for
// example a customer-data export API). After the client sends
// "RATE <bytes/sec>\n" it streams data at that rate until the connection
// closes.
package upstream

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"time"
)

// Server streams rate-limited data to each connection.
type Server struct{ ln net.Listener }

// Start listens on addr.
func Start(addr string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	return s, nil
}

// Addr returns the listen address.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Close stops the server.
func (s *Server) Close() { _ = s.ln.Close() }

func serve(c net.Conn) {
	defer c.Close()
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	f := strings.Fields(line)
	if len(f) != 2 || f[0] != "RATE" {
		return
	}
	rate, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil || rate <= 0 {
		return
	}
	const chunk = 16 * 1024
	buf := make([]byte, chunk)
	for i := range buf {
		buf[i] = byte('a' + i%26) // stand-in for customer records
	}
	interval := time.Duration(float64(time.Second) * chunk / float64(rate))
	next := time.Now()
	for {
		if _, err := c.Write(buf); err != nil {
			return
		}
		next = next.Add(interval)
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		}
	}
}
