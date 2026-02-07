package bench

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

type localCertBundle struct {
	CAPool     *x509.CertPool
	ServerCert tls.Certificate
	ClientCert tls.Certificate
}

func newLocalCertBundle() (*localCertBundle, error) {
	now := time.Now()

	// CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName:   "iotbci-bench-ca",
			Organization: []string{"iotbci-bench"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// Server
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName: "iotbci-bench-server",
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
		DNSNames: []string{"localhost"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	serverCert := tls.Certificate{
		Certificate: [][]byte{serverDER, caDER},
		PrivateKey:  serverKey,
	}

	// Client
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject: pkix.Name{
			CommonName: "iotbci-bench-client",
		},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	clientCert := tls.Certificate{
		Certificate: [][]byte{clientDER, caDER},
		PrivateKey:  clientKey,
	}

	return &localCertBundle{
		CAPool:     caPool,
		ServerCert: serverCert,
		ClientCert: clientCert,
	}, nil
}

func randomSerial() *big.Int {
	// Best-effort 128-bit serial.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		// Fallback to time-based serial if rand fails.
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}
