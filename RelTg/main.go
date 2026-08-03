package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
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
	wsMagic     = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

var (
	token       string
	tokenSource string
	buildTime   = "unknown" // injected: -ldflags "-X main.buildTime=..."
	startedAt   = time.Now()
)

// Telegram production DC IPs. Whitelist ВСЕГДА активен (любой режим).
var tgDCIPs = map[string]bool{
	"149.154.175.50":  true,
	"149.154.167.51":  true,
	"149.154.175.100": true,
	"149.154.167.91":  true,
	"149.154.171.5":   true,
	"91.105.192.100":  true,
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

// ---------- TOKEN at startup (single branch) ----------

func isPaaS() bool {
	for _, k := range []string{
		"RENDER", "RENDER_SERVICE_NAME",
		"RAILWAY_ENVIRONMENT", "RAILWAY_PROJECT_ID",
		"FLY_APP_NAME", "DYNO", "K_SERVICE",
	} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

func initToken() {
	if t := strings.TrimSpace(os.Getenv("TOKEN")); t != "" {
		token = t
		tokenSource = "env"
		return
	}
	if isPaaS() {
		log.Fatalf("TOKEN env is not set. On this platform set TOKEN explicitly in the panel; auto-generation is disabled on PaaS.")
	}
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	token = hex.EncodeToString(b)
	tokenSource = "generated"
	log.Printf("GENERATED TOKEN: %s  (save it, or set TOKEN env for a stable one)", token)
}

func mode() string {
	if tokenSource == "generated" {
		return "PRIVATE (generated token)"
	}
	return "PRIVATE (token)"
}

// ---------- sessions (long-poll) ----------

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
	mu       sync.Mutex
	sessions = map[string]*session{}
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
	return r.URL.Query().Get("tok") == token
}

// allowedDst: whitelist ВСЕГДА (dst только TG DC), независимо от токена.
func allowedDst(dst string) bool {
	host := dst
	if i := strings.LastIndex(dst, ":"); i >= 0 {
		host = dst[:i]
	}
	return tgDCIPs[host]
}

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
				return
			default:
				log.Printf("sid=%s down overflow, closing", sid)
				return
			}
		}
		if err != nil {
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

// ---------- WebSocket (stdlib) ----------

func wsAcceptKey(key string) string {
	h := sha1.New()
	io.WriteString(h, key+wsMagic)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func wsHandshake(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, bool) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, "websocket required", http.StatusBadRequest)
		return nil, nil, false
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "no key", http.StatusBadRequest)
		return nil, nil, false
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, false
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, false
	}
	fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsAcceptKey(key))
	return conn, rw, true
}

func wsReadFrame(rw *bufio.ReadWriter) (byte, []byte, error) {
	b0, err := rw.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	opcode := b0 & 0x0F
	b1, err := rw.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	masked := b1&0x80 != 0
	ln := uint64(b1 & 0x7F)
	switch ln {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(rw, ext[:]); err != nil {
			return 0, nil, err
		}
		ln = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(rw, ext[:]); err != nil {
			return 0, nil, err
		}
		ln = binary.BigEndian.Uint64(ext[:])
	}
	if ln > 1<<20 {
		return 0, nil, fmt.Errorf("frame too large")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(rw, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, ln)
	if _, err := io.ReadFull(rw, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

func wsWriteFrame(w io.Writer, opcode byte, payload []byte) error {
	hdr := []byte{0x80 | opcode}
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		hdr = append(hdr, ext[:]...)
	default:
		hdr = append(hdr, 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, ext[:]...)
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

type wsWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *wsWriter) write(opcode byte, p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return wsWriteFrame(s.w, opcode, p)
}

// /apiws: WS-мост в dst, требует tok.
func handleApiWs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("tok") != token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	dst := normDst(q.Get("dst"))
	if dst == "" || !allowedDst(dst) {
		http.Error(w, "dst not allowed", http.StatusForbidden)
		return
	}
	conn, rw, ok := wsHandshake(w, r)
	if !ok {
		return
	}
	defer conn.Close()
	tcp, err := net.DialTimeout("tcp", dst, dialTimeout)
	if err != nil {
		_ = wsWriteFrame(conn, 8, nil)
		return
	}
	defer tcp.Close()
	ww := &wsWriter{w: conn}
	go func() {
		buf := make([]byte, readBuf)
		for {
			n, err := tcp.Read(buf)
			if n > 0 {
				if werr := ww.write(2, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				_ = ww.write(8, nil)
				return
			}
		}
	}()
	for {
		op, payload, err := wsReadFrame(rw)
		if err != nil {
			return
		}
		switch op {
		case 1, 2:
			if _, err := tcp.Write(payload); err != nil {
				return
			}
		case 8:
			return
		case 9:
			_ = ww.write(10, payload)
		}
	}
}

// /wsecho: публичный эхо-эндпоинт для браузерного WS-теста (без tok, без dst).
func handleWsEcho(w http.ResponseWriter, r *http.Request) {
	conn, rw, ok := wsHandshake(w, r)
	if !ok {
		return
	}
	defer conn.Close()
	for {
		op, payload, err := wsReadFrame(rw)
		if err != nil {
			return
		}
		switch op {
		case 1, 2:
			if err := wsWriteFrame(conn, op, payload); err != nil {
				return
			}
		case 8:
			return
		case 9:
			_ = wsWriteFrame(conn, 10, payload)
		}
	}
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

const pageScript = `<script>
(function(){
var el=document.getElementById('ws');
if(!el||!('WebSocket' in window)){if(el){el.textContent='unsupported';el.className='fail';}return;}
var t0=Date.now();
var proto=location.protocol==='https:'?'wss://':'ws://';
var ws;
try{ws=new WebSocket(proto+location.host+'/wsecho');}catch(e){el.textContent='BLOCKED';el.className='fail';return;}
var to=setTimeout(function(){try{ws.close();}catch(e){}el.textContent='BLOCKED (timeout)';el.className='fail';},5000);
ws.onopen=function(){try{ws.send('ping');}catch(e){}};
ws.onmessage=function(){clearTimeout(to);var ms=Date.now()-t0;el.textContent='OK ('+ms+'ms)';el.className='ok';try{ws.close();}catch(e){}};
ws.onerror=function(){clearTimeout(to);el.textContent='BLOCKED';el.className='fail';};
})();
</script>`

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
	b.WriteString("<h2>Relay: OK</h2>")
	fmt.Fprintf(&b, "<p>uptime %s &middot; %s UTC<br>active sessions: %d<br>mode: %s<br>build: %s</p>",
		time.Since(startedAt).Round(time.Second),
		time.Now().UTC().Format("2006-01-02 15:04:05"),
		n, mode(), buildTime)
	b.WriteString("<table><tr><th>DC</th><th>IP</th><th>status</th><th>rtt</th></tr>")
	for _, row := range rows {
		if row.OK {
			fmt.Fprintf(&b, "<tr><td>DC%d</td><td>%s</td><td class=ok>OK</td><td>%s</td></tr>", row.DC, row.IP, row.RTT)
		} else {
			fmt.Fprintf(&b, "<tr><td>DC%d</td><td>%s</td><td class=fail>FAIL</td><td>%s</td></tr>", row.DC, row.IP, row.Err)
		}
	}
	b.WriteString("</table>")
	b.WriteString("<p>You &rarr; Relay (WSS): <span id=ws>testing&hellip;</span></p>")
	b.WriteString(pageScript)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.String()))
}

// ---------- main ----------

func main() {
	initToken()
	log.Printf("relay build: %s", buildTime)
	log.Printf("relay running in %s", mode())
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
	mux.HandleFunc("/apiws", handleApiWs)
	mux.HandleFunc("/wsecho", handleWsEcho)
	mux.HandleFunc("/", handleIndex)
	log.Printf("relay listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}