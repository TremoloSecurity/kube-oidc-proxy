// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "auth-config-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

func TestLoadAuthenticationConfig_Valid(t *testing.T) {
	yaml := `
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["client1"]
  claimMappings:
    username:
      claim: sub
      prefix: ""
- issuer:
    url: https://issuer2.example.com
    audiences: ["client2"]
  claimMappings:
    username:
      claim: email
      prefix: ""
`
	path := writeTemp(t, yaml)
	providers, err := LoadAuthenticationConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(providers) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(providers))
	}
	if providers[0].Issuer.URL != "https://issuer1.example.com" {
		t.Errorf("provider[0] URL: got %q", providers[0].Issuer.URL)
	}
	if providers[1].Issuer.URL != "https://issuer2.example.com" {
		t.Errorf("provider[1] URL: got %q", providers[1].Issuer.URL)
	}
}

func TestLoadAuthenticationConfig_FileNotFound(t *testing.T) {
	_, err := LoadAuthenticationConfig(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadAuthenticationConfig_InvalidYAML(t *testing.T) {
	path := writeTemp(t, "not: valid: yaml: [[[")
	_, err := LoadAuthenticationConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadAuthenticationConfig_WrongKind(t *testing.T) {
	yaml := `
apiVersion: apiserver.config.k8s.io/v1beta1
kind: EgressSelectorConfiguration
egressSelections: []
`
	path := writeTemp(t, yaml)
	_, err := LoadAuthenticationConfig(path)
	if err == nil {
		t.Fatal("expected error for wrong kind, got nil")
	}
}

func TestLoadAuthenticationConfig_EmptyJWT(t *testing.T) {
	yaml := `
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt: []
`
	path := writeTemp(t, yaml)
	_, err := LoadAuthenticationConfig(path)
	if err == nil {
		t.Fatal("expected error for empty jwt list, got nil")
	}
}

func TestLoadAuthenticationConfig_WithCA(t *testing.T) {
	yaml := `
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://secure-issuer.example.com
    audiences: ["myapp"]
    certificateAuthority: |
      -----BEGIN CERTIFICATE-----
      MIIBvzCCAWWgAwIBAgIRAIx3RHp24GVOUMGaXcbGi9MwCgYIKoZIzj0EAwIwIzEh
      -----END CERTIFICATE-----
  claimMappings:
    username:
      claim: sub
      prefix: ""
`
	path := writeTemp(t, yaml)
	providers, err := LoadAuthenticationConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}
	if providers[0].Issuer.CertificateAuthority == "" {
		t.Error("expected certificateAuthority to be populated")
	}
}
