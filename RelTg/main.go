package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	pollTimeout = 25 * time.Second
	dialTimeout = 10 * time.Second
	downBuf     = 256
	readBuf     = 256 * 1024
	probeTTL    = 30 * time.Second
	probeDial   = 3 * time.Second
)

var token = os.Getenv("RELAY_TOKEN")

// Telegram production DC IPs. В OPEN-режиме (без токена) relay принимает
// dst ТОЛЬКО из этого набора — иначе нода превращается в открытый прокси.
var tgDCIPs = map[string]bool{
	"149.154.175.50": true, // DC1
	"149.154.167.51": true, // DC2
	"149.154.175.100": true, // DC3
	"149.154.167.91": true, // DC4
	"149.154.171.5": true, // DC5
	"91.105.192.100": true, // DC203
}

type probeTarget struct {
	dc int
	ip string
}

var probeTargets = []probeTarget{
	{1, "149.154.175.50"},
	{2, "149.154.167.51"},
	{3, "149.154.175.100"},
	{4, "149.154.167.91"},
	{5, "149.154.171.5"},
	{203, "91.105.192.100"},
}

type session struct {
	conn net.Conn
	down chan []byte
	done chan struct{}
	once sync.Once
}

func (s *session) close() {
	s.once.Do(func() {
		close(s.done)
		_ = s.conn.Close()
	})
}

var (
	mu        sync.Mutex
	sessions  = map[string]*session{}
	startedAt = time.Now()
)

func newSID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func normDst(d string) string {
	if d == "" {
		return ""
	}
	if strings.Contains(d, ":") {
		return d
	}
	return d + ":443"
}

func checkToken(r *http.Request) bool {
	if token == "" {
		return true
	}
	return r.URL.Query().Get("tok") == token
}

// allowedDst: приватный режим (токен задан) — любой dst, владелец доверяет себе.
// OPEN-режим (токена нет) — только Telegram DC, иначе abuse/скан портов.
func allowedDst(dst string) bool {
	if token != "" {
		return true
	}
	host := dst
	if i := strings.LastIndex(dst, ":"); i >= 0 {
		host = dst[:i]
	}
	return tgDCIPs[host]
}

func mode() string {
	if token == "" {
		return "PUBLIC (DC whitelist)"
	}
	return "PRIVATE (token)"
}

// ---------- HTTP long-poll ----------

func readerLoop(s *session, sid string) {
	defer func() {
		s.close()
		mu.Lock()
		delete(sessions, sid)
		mu.Unlock()
		log.Printf("sid=%s reader exited, session removed", sid)
	}()
	buf := make([]byte, readBuf)
	for {
		n, err := s.conn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			select {
			case s.down <- chunk:
			case <-s.done:
				log.Printf("sid=%s reader: done closed (client /close)", sid)
				return
			default:
				log.Printf("sid=%s down overflow, closing", sid)
				return
			}
		}
		if err != nil {
			log.Printf("sid=%s reader: conn read err: %v", sid, err)
			return
		}
	}
}

func handleOpen(w http.ResponseWriter, r *http.Request) {
	if !checkToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	dst := normDst(r.URL.Query().Get("dst"))
	if dst == "" {
		http.Error(w, "dst required", http.StatusBadRequest)
		return
	}
	if !allowedDst(dst) {
		http.Error(w, "dst not allowed", http.StatusForbidden)
		return
	}
	conn, err := net.DialTimeout("tcp", dst, dialTimeout)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": err.Error()})
		return
	}
	s := &session{conn: conn, down: make(chan []byte, downBuf), done: make(chan struct{})}
	sid := newSID()
	mu.Lock()
	sessions[sid] = s
	mu.Unlock()
	go readerLoop(s, sid)
	log.Printf("sid=%s open dst=%s", sid, dst)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "sid": sid})
}

func handleUp(w http.ResponseWriter, r *http.Request) {
	if !checkToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	mu.Lock()
	s := sessions[r.URL.Query().Get("sid")]
	mu.Unlock()
	if s == nil {
		http.Error(w, "no session", http.StatusGone)
		return
	}
	if _, err := io.Copy(s.conn, r.Body); err != nil {
		log.Printf("sid up write err: %v", err)
		s.close()
		http.Error(w, "write failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func handleDown(w http.ResponseWriter, r *http.Request) {
	if !checkToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	mu.Lock()
	s := sessions[r.URL.Query().Get("sid")]
	mu.Unlock()
	if s == nil {
		w.WriteHeader(http.StatusGone)
		return
	}
	select {
	case chunk, ok := <-s.down:
		if !ok {
			w.WriteHeader(http.StatusGone)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(chunk)
	case <-time.After(pollTimeout):
		w.WriteHeader(http.StatusNoContent)
	case <-r.Context().Done():
	}
}

func handleClose(w http.ResponseWriter, r *http.Request) {
	if !checkToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sid := r.URL.Query().Get("sid")
	mu.Lock()
	s := sessions[sid]
	delete(sessions, sid)
	mu.Unlock()
	if s != nil {
		s.close()
	}
	w.WriteHeader(http.StatusOK)
}

func handleProbe(w http.ResponseWriter, r *http.Request) {
	if !checkToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	dst := normDst(r.URL.Query().Get("dst"))
	if dst == "" || !allowedDst(dst) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": "dst not allowed"})
		return
	}
	conn, err := net.DialTimeout("tcp", dst, dialTimeout)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "err": err.Error()})
		return
	}
	_ = conn.Close()
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// ---------- диагностика / ----------

type probeRow struct {
	DC  int
	IP  string
	OK  bool
	RTT string
	Err string
}

var (
	prMu    sync.Mutex
	prAt    time.Time
	prCache []probeRow
)

func runProbes() []probeRow {
	prMu.Lock()
	if prCache != nil && time.Since(prAt) < probeTTL {
		c := prCache
		prMu.Unlock()
		return c
	}
	prMu.Unlock()

	rows := make([]probeRow, len(probeTargets))
	var wg sync.WaitGroup
	for i, t := range probeTargets {
		wg.Add(1)
		go func(i int, t probeTarget) {
			defer wg.Done()
			addr := t.ip + ":443"
			start := time.Now()
			c, err := net.DialTimeout("tcp", addr, probeDial)
			d := time.Since(start)
			if err == nil {
				_ = c.Close()
				rows[i] = probeRow{t.dc, t.ip, true, d.Round(time.Millisecond).String(), ""}
			} else {
				rows[i] = probeRow{t.dc, t.ip, false, "", err.Error()}
			}
		}(i, t)
	}
	wg.Wait()

	prMu.Lock()
	prCache = rows
	prAt = time.Now()
	prMu.Unlock()
	return rows
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	rows := runProbes()
	mu.Lock()
	n := len(sessions)
	mu.Unlock()

	var b strings.Builder
	b.WriteString("<!doctype html><meta charset=utf-8><title>Relay</title>")
	b.WriteString("<style>body{font-family:monospace;margin:2em;line-height:1.5}" +
		".ok{color:#0a0}.fail{color:#c00}td{padding:2px 14px}" +
		"table{border-collapse:collapse}th{text-align:left}</style>")
	fmt.Fprintf(&b, "<h2>Relay: OK</h2>")
	fmt.Fprintf(&b, "<p>uptime %s &middot; %s UTC<br>active sessions: %d<br>mode: %s</p>",
		time.Since(startedAt).Round(time.Second),
		time.Now().UTC().Format("2006-01-02 15:04:05"),
		n, mode())
	b.WriteString("<table><tr><th>DC</th><th>IP</th><th>status</th><th>rtt</th></tr>")
	for _, row := range rows {
		if row.OK {
			fmt.Fprintf(&b, "<tr><td>DC%d</td><td>%s</td><td class=ok>OK</td><td>%s</td></tr>",
				row.DC, row.IP, row.RTT)
		} else {
			fmt.Fprintf(&b, "<tr><td>DC%d</td><td>%s</td><td class=fail>FAIL</td><td>%s</td></tr>",
				row.DC, row.IP, row.Err)
		}
	}
	b.WriteString("</table>")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.String()))
}

// ---------- main ----------

func main() {
	if token == "" {
		log.Println("WARNING: RELAY_TOKEN not set — PUBLIC mode, dst limited to Telegram DC whitelist")
	} else {
		log.Println("relay running in PRIVATE mode (token required)")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "80"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/open", handleOpen)
	mux.HandleFunc("/up", handleUp)
	mux.HandleFunc("/down", handleDown)
	mux.HandleFunc("/close", handleClose)
	mux.HandleFunc("/probe", handleProbe)
	mux.HandleFunc("/", handleIndex)
	log.Printf("relay listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}