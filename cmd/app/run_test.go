// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	apiserverapi "k8s.io/apiserver/pkg/apis/apiserver"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"

	"github.com/jetstack/kube-oidc-proxy/cmd/app/options"
)

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "auth-config-*.yaml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing temp file: %v", err)
	}
	return f.Name()
}

func TestOIDCAutherFromJWT_Construction(t *testing.T) {
	emptyPrefix := ""
	entry := apiserverapi.JWTAuthenticator{
		Issuer: apiserverapi.Issuer{
			URL:       "https://vault.example.com/v1/identity/oidc",
			Audiences: []string{"my-client"},
		},
		ClaimMappings: apiserverapi.ClaimMappings{
			Username: apiserverapi.PrefixedClaimOrExpression{
				Claim:  "email",
				Prefix: &emptyPrefix,
			},
			Groups: apiserverapi.PrefixedClaimOrExpression{
				Claim:  "groups",
				Prefix: &emptyPrefix,
			},
		},
		UserValidationRules: []apiserverapi.UserValidationRule{
			{Expression: "!user.username.startsWith('system:')", Message: "no system: prefix"},
		},
	}

	auther, err := oidcAutherFromJWT(entry, authenticationcel.NewDefaultCompiler(), []string{"RS256"})
	if err != nil {
		t.Fatalf("oidcAutherFromJWT() unexpected error: %v", err)
	}
	if auther == nil {
		t.Error("oidcAutherFromJWT() returned nil authenticator")
	}
}

func TestBuildTokenAuther_SingleIssuer(t *testing.T) {
	opts := &options.Options{
		OIDCAuthentication: &options.OIDCAuthenticationOptions{
			IssuerURL:     "https://vault.example.com/v1/identity/oidc",
			ClientID:      "my-client",
			UsernameClaim: "email",
			GroupsClaim:   "groups",
			SigningAlgs:   []string{"RS256"},
		},
		AuthenticationConfig: &options.AuthenticationConfigOptions{},
	}

	auther, issuerURLs, err := buildTokenAuther(opts)
	if err != nil {
		t.Fatalf("buildTokenAuther() unexpected error: %v", err)
	}
	if auther == nil {
		t.Error("buildTokenAuther() returned nil authenticator")
	}
	if want := []string{opts.OIDCAuthentication.IssuerURL}; len(issuerURLs) != len(want) || issuerURLs[0] != want[0] {
		t.Errorf("buildTokenAuther() issuerURLs = %v, want %v", issuerURLs, want)
	}
}

func TestBuildTokenAuther_AuthConfig(t *testing.T) {
	configContent := `
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt:
  - issuer:
      url: https://vault.example.com/v1/identity/oidc
      audiences:
        - my-client
    claimMappings:
      username:
        claim: email
        prefix: ""
      groups:
        claim: groups
        prefix: ""
  - issuer:
      url: https://issuer2.example.com/v1/identity/oidc
      audiences:
        - kubernetes
    claimMappings:
      username:
        claim: email
        prefix: ""
      groups:
        claim: groups
        prefix: ""
`
	configPath := writeTempFile(t, configContent)

	opts := &options.Options{
		OIDCAuthentication: &options.OIDCAuthenticationOptions{
			SigningAlgs: []string{"RS256"},
		},
		AuthenticationConfig: &options.AuthenticationConfigOptions{
			ConfigFile: configPath,
		},
	}

	auther, issuerURLs, err := buildTokenAuther(opts)
	if err != nil {
		t.Fatalf("buildTokenAuther() unexpected error: %v", err)
	}
	if auther == nil {
		t.Error("buildTokenAuther() returned nil authenticator")
	}
	want := []string{
		"https://vault.example.com/v1/identity/oidc",
		"https://issuer2.example.com/v1/identity/oidc",
	}
	if len(issuerURLs) != len(want) {
		t.Fatalf("buildTokenAuther() issuerURLs = %v, want %v", issuerURLs, want)
	}
	for i := range want {
		if issuerURLs[i] != want[i] {
			t.Errorf("buildTokenAuther() issuerURLs[%d] = %q, want %q", i, issuerURLs[i], want[i])
		}
	}
}

func TestBuildUnionAutherFromV1ConfigWithCEL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.yaml")
	cfg := `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one"]
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
    groups:
      expression: '["g:" + claims.owner]'
- issuer:
    url: https://issuer2.example.com
    audiences: ["aud-two"]
  claimMappings:
    username:
      claim: sub
      prefix: "two:"
`
	if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}

	opts := options.New()
	opts.AuthenticationConfig.ConfigFile = path

	auther, issuerURLs, err := buildTokenAuther(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auther == nil {
		t.Fatal("expected a token authenticator, got nil")
	}
	want := []string{"https://issuer1.example.com", "https://issuer2.example.com"}
	if !reflect.DeepEqual(issuerURLs, want) {
		t.Fatalf("expected issuer URLs %v, got %v", want, issuerURLs)
	}
}

func TestBuildTokenAuther_AuthConfig_InvalidFile(t *testing.T) {
	opts := &options.Options{
		OIDCAuthentication:   &options.OIDCAuthenticationOptions{SigningAlgs: []string{"RS256"}},
		AuthenticationConfig: &options.AuthenticationConfigOptions{ConfigFile: "/does/not/exist.yaml"},
	}

	_, _, err := buildTokenAuther(opts)
	if err == nil {
		t.Error("buildTokenAuther() expected error for missing config file, got nil")
	}
}
