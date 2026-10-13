// Package tlsutil generates and loads the TLS material used by the control
// plane. The control channel is separate from the public HTTP tunnels (which
// are terminated by Caddy), so it needs its own certificate.
//
// By default the server generates a self-signed certificate on first start and
// persists it under the data directory. The client can then either trust that
// certificate explicitly (--ca) or pin it on first use.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EnsureSelfSigned loads cert.pem/key.pem from dir, generating them if they do
// not exist — or regenerating when the existing certificate no longer covers
// every requested host. Without that check a change to --control-addr or
// --control-hosts would be silently ignored until someone deleted the file by
// hand. It returns the certificate and its SHA-256 fingerprint.
func EnsureSelfSigned(dir string, hosts []string) (tls.Certificate, string, error) {
	certPath := filepath.Join(dir, "control-cert.pem")
	keyPath := filepath.Join(dir, "control-key.pem")

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err == nil && coversAll(cert, hosts) {
				return cert, Fingerprint(cert.Certificate[0]), nil
			}
			// Either unreadable or missing a SAN we now need: replace it.
		}
	}

	cert, der, err := Generate(hosts)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := writePair(certPath, keyPath, cert, der); err != nil {
		return tls.Certificate{}, "", err
	}
	return cert, Fingerprint(der), nil
}

// coversAll reports whether the certificate is valid for every host.
func coversAll(cert tls.Certificate, hosts []string) bool {
	if len(cert.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	for _, h := range hosts {
		// A wildcard SAN cannot be verified against itself — the pattern is
		// only meaningful when matched from the other side. Skip it so that
		// adding a concrete host still triggers regeneration.
		if strings.Contains(h, "*") {
			continue
		}
		if leaf.VerifyHostname(h) != nil {
			return false
		}
	}
	return true
}

// Generate creates an in-memory self-signed certificate valid for one year.
func Generate(hosts []string) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "aritun-control", Organization: []string{"AriTun"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	cert.Leaf, _ = x509.ParseCertificate(der)
	return cert, der, nil
}

// Fingerprint returns the hex SHA-256 of a DER certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// LocalIPs returns every unicast address this machine owns, excluding
// loopback. Certificates bound to ":9443" cover all interfaces but the SANs
// only match if we name them, and clients dial the address they can reach —
// which on a VPS is the public IP.
func LocalIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP == nil || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			if v4 := ipnet.IP.To4(); v4 != nil {
				out = append(out, v4.String())
				continue
			}
			if v6 := ipnet.IP.To16(); v6 != nil {
				out = append(out, v6.String())
			}
		}
	}
	return out
}

// LoadPool builds a certificate pool from a PEM file, or the system pool when
// path is empty.
func LoadPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return x509.SystemCertPool()
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

func writePair(certPath, keyPath string, cert tls.Certificate, der []byte) error {
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		certOut.Close()
		return err
	}
	certOut.Close()

	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("unexpected key type %T", cert.PrivateKey)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	return pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
