package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

type demoReport struct {
	GeneratedAt time.Time `json:"generated_at"`
	Messages    int       `json:"messages"`

	SentClasses     []string `json:"sent_classes"`
	EchoClasses     []string `json:"echo_classes"`
	MITMSeenClasses []string `json:"mitm_seen_classes"`

	RecoverRate float64 `json:"recover_rate"`
	Success     bool    `json:"success"`
	Error       string  `json:"error,omitempty"`
}

func main() {
	var (
		outPath  = flag.String("out", "", "output JSON path (default: stdout)")
		messages = flag.Int("messages", 64, "number of BCI messages")
		timeout  = flag.Duration("timeout", 15*time.Second, "overall timeout")
	)
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	rep := demoReport{
		GeneratedAt: time.Now(),
		Messages:    *messages,
	}
	if *messages <= 0 {
		rep.Error = "messages must be > 0"
		writeReport(*outPath, rep)
		return
	}

	sentClasses := buildClasses(*messages)
	rep.SentClasses = append(rep.SentClasses, sentClasses...)

	rootPEM, caKey, caCert, err := newCA("IoTBCI MITM Root")
	if err != nil {
		rep.Error = err.Error()
		writeReport(*outPath, rep)
		return
	}

	originTLS, err := newLeafTLSConfig(caCert, caKey, "origin.local")
	if err != nil {
		rep.Error = err.Error()
		writeReport(*outPath, rep)
		return
	}
	mitmTLS, err := newLeafTLSConfig(caCert, caKey, "origin.local")
	if err != nil {
		rep.Error = err.Error()
		writeReport(*outPath, rep)
		return
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		rep.Error = "failed to append root cert"
		writeReport(*outPath, rep)
		return
	}

	originLn, err := tls.Listen("tcp", "127.0.0.1:0", originTLS)
	if err != nil {
		rep.Error = err.Error()
		writeReport(*outPath, rep)
		return
	}
	defer originLn.Close()

	originErrCh := make(chan error, 1)
	go func() {
		originErrCh <- serveOriginEcho(ctx, originLn)
	}()

	mitmLn, err := tls.Listen("tcp", "127.0.0.1:0", mitmTLS)
	if err != nil {
		rep.Error = err.Error()
		writeReport(*outPath, rep)
		return
	}
	defer mitmLn.Close()

	mitmSeenCh := make(chan []string, 1)
	mitmErrCh := make(chan error, 1)
	go func() {
		seen, err := serveMITM(ctx, mitmLn, originLn.Addr().String(), pool)
		if err != nil {
			mitmErrCh <- err
			return
		}
		mitmSeenCh <- seen
	}()

	echo, cliErr := runClient(ctx, mitmLn.Addr().String(), pool, sentClasses)
	rep.EchoClasses = append(rep.EchoClasses, echo...)
	if cliErr != nil {
		rep.Error = cliErr.Error()
		writeReport(*outPath, rep)
		return
	}

	select {
	case seen := <-mitmSeenCh:
		rep.MITMSeenClasses = append(rep.MITMSeenClasses, seen...)
	case err := <-mitmErrCh:
		rep.Error = err.Error()
		writeReport(*outPath, rep)
		return
	case <-ctx.Done():
		rep.Error = ctx.Err().Error()
		writeReport(*outPath, rep)
		return
	}

	_ = originLn.Close()
	select {
	case <-originErrCh:
	case <-time.After(100 * time.Millisecond):
	}

	rep.RecoverRate = recoverRate(rep.SentClasses, rep.MITMSeenClasses)
	rep.Success = rep.RecoverRate >= 0.999 && recoverRate(rep.SentClasses, rep.EchoClasses) >= 0.999
	writeReport(*outPath, rep)
}

func writeReport(outPath string, rep demoReport) {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if outPath == "" {
		_, _ = os.Stdout.Write(append(b, '\n'))
		return
	}
	if err := os.WriteFile(outPath, append(b, '\n'), 0o644); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func buildClasses(n int) []string {
	classes := []string{"left", "right", "blink", "rest", "focus", "relax"}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = classes[(i*5+i/3)%len(classes)]
	}
	return out
}

func classLine(cls string, idx int) string {
	return fmt.Sprintf("BCI_CLASS=%s|seq=%04d\n", cls, idx)
}

func parseClass(line string) string {
	const prefix = "BCI_CLASS="
	if !strings.HasPrefix(line, prefix) {
		return ""
	}
	body := strings.TrimPrefix(line, prefix)
	if i := strings.IndexByte(body, '|'); i >= 0 {
		body = body[:i]
	}
	return strings.TrimSpace(body)
}

func runClient(ctx context.Context, mitmAddr string, roots *x509.CertPool, classes []string) ([]string, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", mitmAddr)
	if err != nil {
		return nil, err
	}
	defer raw.Close()

	tc := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: "origin.local",
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	defer tc.Close()

	rd := bufio.NewReader(tc)
	wr := bufio.NewWriter(tc)
	echo := make([]string, 0, len(classes))
	for i, cls := range classes {
		if _, err := wr.WriteString(classLine(cls, i)); err != nil {
			return echo, err
		}
		if err := wr.Flush(); err != nil {
			return echo, err
		}
		line, err := rd.ReadString('\n')
		if err != nil {
			return echo, err
		}
		echo = append(echo, parseClass(strings.TrimSpace(line)))
	}
	return echo, nil
}

func serveOriginEcho(ctx context.Context, ln net.Listener) error {
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()

	rd := bufio.NewReader(conn)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := rd.ReadString('\n')
		if err != nil {
			return nil
		}
		if _, err := conn.Write([]byte(line)); err != nil {
			return nil
		}
	}
}

func serveMITM(ctx context.Context, ln net.Listener, originAddr string, roots *x509.CertPool) ([]string, error) {
	cconn, err := ln.Accept()
	if err != nil {
		return nil, err
	}
	defer cconn.Close()

	originConn, err := tls.Dial("tcp", originAddr, &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: "origin.local",
	})
	if err != nil {
		return nil, err
	}
	defer originConn.Close()

	cliReader := bufio.NewReader(cconn)
	originReader := bufio.NewReader(originConn)
	seen := make([]string, 0, 128)

	for {
		select {
		case <-ctx.Done():
			return seen, ctx.Err()
		default:
		}
		line, err := cliReader.ReadString('\n')
		if err != nil {
			return seen, nil
		}
		if cls := parseClass(strings.TrimSpace(line)); cls != "" {
			seen = append(seen, cls)
		}

		if _, err := originConn.Write([]byte(line)); err != nil {
			return seen, err
		}
		back, err := originReader.ReadString('\n')
		if err != nil {
			return seen, err
		}
		if _, err := cconn.Write([]byte(back)); err != nil {
			return seen, err
		}
	}
}

func recoverRate(sent, seen []string) float64 {
	if len(sent) == 0 {
		return 0
	}
	n := len(sent)
	if len(seen) < n {
		n = len(seen)
	}
	if n == 0 {
		return 0
	}
	ok := 0
	for i := 0; i < n; i++ {
		if sent[i] == seen[i] {
			ok++
		}
	}
	return float64(ok) / float64(len(sent))
}

func newCA(cn string) ([]byte, *ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return p, key, cert, nil
}

func newLeafTLSConfig(ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsName string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		DNSNames:    []string{dnsName},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}, nil
}
