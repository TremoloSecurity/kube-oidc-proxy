// Copyright Jetstack Ltd. See LICENSE for details.
package issuer

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"
)

type Issuer struct {
	issuerURL         string
	keyFile, certFile string
	clientCAFile      string

	sk *rsa.PrivateKey

	stopCh <-chan struct{}
}

func New(issuerURL, keyFile, certFile, clientCAFile string, stopCh <-chan struct{}) (*Issuer, error) {
	b, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil,
			fmt.Errorf("failed to parse PEM block containing the key: %q", keyFile)
	}

	sk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &Issuer{
		keyFile:      keyFile,
		certFile:     certFile,
		clientCAFile: clientCAFile,
		issuerURL:    issuerURL,
		sk:           sk,
		stopCh:       stopCh,
	}, nil
}

func (i *Issuer) Run(bindAddress, listenPort string) (<-chan struct{}, error) {
	serveAddr := fmt.Sprintf("%s:%s", bindAddress, listenPort)

	l, err := net.Listen("tcp", serveAddr)
	if err != nil {
		return nil, err
	}

	go func() {
		<-i.stopCh
		if l != nil {
			l.Close()
		}
	}()

	compCh := make(chan struct{})
	go func() {
		defer close(compCh)

		config, err := i.setupTLSConfig()
		if err != nil {
			log.Errorf("failed to setup TLS config: %v", err)
			return
		}

		server := http.Server{Handler: i,
			TLSConfig: config,
		}

		err = server.ServeTLS(l, i.certFile, i.keyFile)
		if err != nil {
			log.Errorf("stopped serving TLS (%s): %s", serveAddr, err)
		}
	}()

	log.Infof("mock issuer listening and serving on %s", serveAddr)

	return compCh, nil
}

func (i *Issuer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	log.Infof("mock issuer received url %s", r.URL)

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	switch r.URL.String() {
	case "/.well-known/openid-configuration":
		rw.WriteHeader(http.StatusOK)

		if _, err := rw.Write(i.wellKnownResponse()); err != nil {
			log.Errorf("failed to write openid-configuration response: %s", err)
		}

	case "/certs":
		rw.WriteHeader(http.StatusOK)

		certsDiscovery := i.certsDiscovery()
		if _, err := rw.Write(certsDiscovery); err != nil {
			log.Errorf("failed to write certificate discovery response: %s", err)
		}

	default:
		log.Errorf("unexpected URL request: %s", r.URL)
		rw.WriteHeader(http.StatusNotFound)
		if _, err := rw.Write([]byte("{}\n")); err != nil {
			log.Errorf("failed to write data to resposne: %s", err)
		}
	}
}

// setupTLSConfig sets up a tls.Config object suitable for use with the issuer's
// HTTPS server.  If mTLS is not enabled then this returns a simple config
// object.  If mTLS is enabled then the TLS config object is set up to verify
// incoming client certificates.
func (i *Issuer) setupTLSConfig() (*tls.Config, error) {
	config := &tls.Config{ClientAuth: tls.NoClientCert}
	if i.clientCAFile != "" {
		log.Infof("mock issuer requiring client certificates")

		pool := x509.NewCertPool()
		caBundle, err := os.ReadFile(i.clientCAFile)
		if err != nil {
			log.Errorf("failed to read CA bundle: %v", err)
			return nil, err
		}

		if !pool.AppendCertsFromPEM(caBundle) {
			log.Errorf("failed to parse CA bundle")
			return nil, err
		}

		config.ClientCAs = pool

		// Unfortunately, the utility used to generate the self-signed
		// certificates used in the test is hardcoded to specify an extended key
		// usage of "server auth" therefore we need to override the certificate
		// verification to skip checking the certificate's extended key usage
		// otherwise the test would fail as the server expects a certificate
		// with a usage of "client auth".
		// Alternatively, the certificate utility could have been cloned simply
		// to override the extended key usage, but for the purpose this test
		// customizing the verification handling is far simpler.
		config.ClientAuth = tls.RequestClientCert
		config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			opts := x509.VerifyOptions{
				Roots:       pool,
				CurrentTime: time.Now(),
				// As per comment above, ignore key usage since the utility is
				// not able to set it to the right value for these tests.
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}

			if len(rawCerts) == 0 {
				return fmt.Errorf("no client certificates provided")
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			log.Infof("verifying certificate for client '%s'", cert.Subject)
			_, err = cert.Verify(opts)
			return err
		}
	}

	return config, nil
}

func (i *Issuer) wellKnownResponse() []byte {
	return []byte(fmt.Sprintf(`{
 "issuer": "%s",
 "jwks_uri": "%s/certs",
 "subject_types_supported": [
  "public"
 ],
 "id_token_signing_alg_values_supported": [
  "RS256"
 ],
 "scopes_supported": [
  "openid",
  "email"
 ],
 "token_endpoint_auth_methods_supported": [
  "client_secret_post",
  "client_secret_basic"
 ],
 "claims_supported": [
  "email",
	"e2e-username-claim",
	"e2e-groups-claim",
  "sub"
 ],
 "code_challenge_methods_supported": [
  "plain",
  "S256"
 ]
}`, i.issuerURL, i.issuerURL))
}

func (i *Issuer) certsDiscovery() []byte {
	n := base64.RawURLEncoding.EncodeToString(i.sk.N.Bytes())

	return []byte(fmt.Sprintf(`{
	  "keys": [
	    {
	      "kid": "0905d6f9cd9b0f1f852e8b207e8f673abca4bf75",
	      "e": "AQAB",
	      "kty": "RSA",
	      "alg": "RS256",
	      "n": "%s",
	      "use": "sig"
	    }
	  ]
	}`, n))
}
