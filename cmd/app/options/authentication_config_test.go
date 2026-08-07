// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
)

func writeAuthConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validV1Config = `apiVersion: apiserver.config.k8s.io/v1
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
  claimValidationRules:
  - expression: 'claims.owner == "my-org"'
    message: "only my-org"
- issuer:
    url: https://issuer2.example.com
    audiences: ["aud-two"]
  claimMappings:
    username:
      claim: sub
      prefix: "two:"
`

const validV1Beta1Config = `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one"]
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
`

func TestAuthenticationConfigLoad(t *testing.T) {
	compiler := authenticationcel.NewDefaultCompiler()

	tests := []struct {
		name        string
		config      string
		wantErr     string // substring; empty means expect success
		wantIssuers int
	}{
		{
			name:        "valid v1 with CEL mappings and validation rules",
			config:      validV1Config,
			wantIssuers: 2,
		},
		{
			name:        "valid v1beta1",
			config:      validV1Beta1Config,
			wantIssuers: 1,
		},
		{
			name: "wrong kind rejected",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthorizationConfiguration
authorizers: []
`,
			wantErr: "expected AuthenticationConfiguration",
		},
		{
			name: "unknown field rejected (strict decoding)",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiencess: ["typo"]
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
`,
			wantErr: "unknown field",
		},
		{
			name: "duplicate issuer URLs rejected",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one"]
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-two"]
  claimMappings:
    username:
      claim: sub
      prefix: "two:"
`,
			wantErr: "Duplicate value",
		},
		{
			name: "invalid CEL expression rejected",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one"]
  claimMappings:
    username:
      expression: 'claims.'
`,
			wantErr: "compilation failed",
		},
		{
			name: "anonymous section rejected",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
anonymous:
  enabled: true
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one"]
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
`,
			wantErr: "not supported",
		},
		{
			name: "empty jwt list rejected",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt: []
`,
			wantErr: "must not be empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := &AuthenticationConfigOptions{ConfigFile: writeAuthConfig(t, tc.config)}
			cfg, err := opts.Load(compiler)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cfg.JWT) != tc.wantIssuers {
				t.Fatalf("expected %d issuers, got %d", tc.wantIssuers, len(cfg.JWT))
			}
		})
	}
}

func TestAuthenticationConfigLoadMissingFile(t *testing.T) {
	opts := &AuthenticationConfigOptions{ConfigFile: "/does/not/exist.yaml"}
	if _, err := opts.Load(authenticationcel.NewDefaultCompiler()); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
