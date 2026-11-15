// Command demo runs the full system on loopback and measures how fast a bulk
// exfiltration is cut off.
//
// Topology (all real TCP sockets):
//
//	client --data--> gw-a --+--> upstream (protected resource)
//	client --data--> gw-b --+
//	gw-a, gw-b <--control channel (signed)--> control plane (detector)
//
// Each trial opens a fresh session that downloads at -rate through gw-a while
// a normal session downloads slowly through gw-b. The control plane must
// detect the bulk session, revoke it on both gateways and collect both ACKs.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"github.com/trianglepotato/revokd/internal/client"
	"github.com/trianglepotato/revokd/internal/control"
	"github.com/trianglepotato/revokd/internal/controlplane"
	"github.com/trianglepotato/revokd/internal/gateway"
	"github.com/trianglepotato/revokd/internal/upstream"
	"github.com/trianglepotato/revokd/kit/idgen"
)

type trial struct {
	Session          string  `json:"session"`
	DetectToAllAckMs float64 `json:"detect_to_all_ack_ms"`
	CrossToCutMs     float64 `json:"threshold_cross_to_cut_ms"`
	OvershootBytes   int64   `json:"overshoot_bytes"`
	FlowsClosed      int     `json:"flows_closed"`
	ReconnectDenied  bool    `json:"reconnect_denied"`
}

type summary struct {
	Config struct {
		Trials      int    `json:"trials"`
		ExfilRate   int64  `json:"exfil_rate_bytes_per_sec"`
		NormalRate  int64  `json:"normal_rate_bytes_per_sec"`
		Threshold   int64  `json:"threshold_bytes"`
		Window      string `json:"window"`
		ReportEvery string `json:"report_every"`
		Gateways    int    `json:"gateways"`
		Measured    string `json:"measured_at"`
		Environment string `json:"environment"`
	} `json:"config"`
	DetectToAllAck  stats   `json:"detect_to_all_ack_ms"`
	CrossToCut      stats   `json:"threshold_cross_to_cut_ms"`
	OvershootMB     stats   `json:"overshoot_mb"`
	ReconnectDenied string  `json:"reconnect_denied"`
	FalsePositives  int     `json:"false_positives"`
	Trials          []trial `json:"trials"`
}

type stats struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	Max float64 `json:"max"`
}

func pct(xs []float64) stats {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	at := func(q float64) float64 {
		i := int(q*float64(len(s)-1) + 0.5)
		return s[i]
	}
	return stats{P50: at(0.50), P95: at(0.95), Max: s[len(s)-1]}
}

func main() {
	trials := flag.Int("trials", 30, "number of exfiltration trials")
	rate := flag.Int64("rate", 20<<20, "exfil download rate (bytes/sec)")
	normal := flag.Int64("normal-rate", 512<<10, "normal session rate (bytes/sec)")
	threshold := flag.Int64("threshold", 5<<20, "bytes per window that trigger revoke")
	window := flag.Duration("window", 2*time.Second, "detection window")
	report := flag.Duration("report", 50*time.Millisecond, "gateway usage report interval")
	out := flag.String("out", "results.json", "result file")
	audit := flag.String("audit", "audit.log", "audit log (JSON lines)")
	flag.Parse()

	ctlKey, tokenKey := []byte(idgen.New()), []byte(idgen.New())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	up, err := upstream.Start("127.0.0.1:0")
	must(err)
	af, err := os.Create(*audit)
	must(err)
	defer af.Close()

	plane := controlplane.New(controlplane.Config{
		Listen: "127.0.0.1:0", Key: ctlKey, Window: *window,
		ThresholdBytes: *threshold, Audit: af,
	})
	must(plane.Start(ctx))
	mk := func(id string) *gateway.Gateway {
		g := gateway.New(gateway.Config{
			ID: id, Listen: "127.0.0.1:0", Upstream: up.Addr(), Control: plane.Addr(),
			Key: ctlKey, TokenKey: tokenKey, ReportEvery: *report,
		})
		must(g.Start(ctx))
		return g
	}
	gwA, gwB := mk("gw-a"), mk("gw-b")
	if !plane.WaitGateways(2, 3*time.Second) {
		log.Fatal("gateways did not register")
	}
	time.Sleep(300 * time.Millisecond)

	var s summary
	s.Config.Trials, s.Config.ExfilRate, s.Config.NormalRate = *trials, *rate, *normal
	s.Config.Threshold, s.Config.Window, s.Config.ReportEvery = *threshold, window.String(), report.String()
	s.Config.Gateways, s.Config.Measured = 2, time.Now().Format(time.RFC3339)
	s.Config.Environment = "single host, loopback TCP, Go " + goVersion()

	var d2a, c2c, over []float64
	denied := 0
	for i := 0; i < *trials; i++ {
		sid := fmt.Sprintf("exfil-%02d", i)
		nsid := fmt.Sprintf("normal-%02d", i)

		// normal user on the other gateway during the whole trial
		nc, nr, err := client.Dial(gwB.Addr(), nsid, control.SessionToken(tokenKey, nsid), *normal)
		must(err)
		normalDone := make(chan client.Result, 1)
		go func() { normalDone <- client.Drain(nc, nr, 0, 0, 1500*time.Millisecond) }()

		c, r, err := client.Dial(gwA.Addr(), sid, control.SessionToken(tokenKey, sid), *rate)
		must(err)
		res := client.Drain(c, r, *threshold, 0, 10*time.Second)

		var rec controlplane.Record
		select {
		case rec = <-plane.Records():
		case <-time.After(3 * time.Second):
			log.Fatalf("trial %d: no revoke record", i)
		}
		if rec.SessionID != sid {
			s.FalsePositives++
			log.Fatalf("trial %d: revoked %s instead of %s", i, rec.SessionID, sid)
		}
		if nres := <-normalDone; nres.CutByRemote {
			s.FalsePositives++
		}

		_, _, err = client.Dial(gwB.Addr(), sid, control.SessionToken(tokenKey, sid), 1024)
		var de *client.DeniedError
		ok := errors.As(err, &de) && de.Reason == "revoked"
		if ok {
			denied++
		}

		t := trial{
			Session:          sid,
			DetectToAllAckMs: ms(rec.AllAckedAt.Sub(rec.DetectedAt)),
			CrossToCutMs:     ms(res.ClosedAt.Sub(res.CrossedAt)),
			OvershootBytes:   res.Total - *threshold,
			FlowsClosed:      rec.Acks["gw-a"].FlowsClosed,
			ReconnectDenied:  ok,
		}
		s.Trials = append(s.Trials, t)
		d2a = append(d2a, t.DetectToAllAckMs)
		c2c = append(c2c, t.CrossToCutMs)
		over = append(over, float64(t.OvershootBytes)/(1<<20))
		time.Sleep(100 * time.Millisecond)
	}
	s.DetectToAllAck, s.CrossToCut, s.OvershootMB = pct(d2a), pct(c2c), pct(over)
	s.ReconnectDenied = fmt.Sprintf("%d/%d", denied, *trials)

	b, _ := json.MarshalIndent(s, "", "  ")
	must(os.WriteFile(*out, b, 0o644))

	fmt.Printf("trials=%d  exfil=%.0f MB/s  threshold=%.0f MB/%s  report=%s  gateways=2 (active-active)\n",
		*trials, float64(*rate)/(1<<20), float64(*threshold)/(1<<20), *window, *report)
	fmt.Printf("%-34s %8s %8s %8s\n", "metric", "p50", "p95", "max")
	row := func(n string, x stats) { fmt.Printf("%-34s %8.2f %8.2f %8.2f\n", n, x.P50, x.P95, x.Max) }
	row("detect -> all gateway ACK (ms)", s.DetectToAllAck)
	row("threshold cross -> flow cut (ms)", s.CrossToCut)
	row("overshoot past threshold (MB)", s.OvershootMB)
	fmt.Printf("reconnect after revoke denied: %s   false positives: %d\n", s.ReconnectDenied, s.FalsePositives)
	fmt.Printf("wrote %s and %s\n", *out, *audit)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
