// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestOidcFlagsChanged(t *testing.T) {
	tests := map[string]struct {
		changedFlags []string
		want         bool
	}{
		"no flags changed": {
			want: false,
		},
		"oidc-issuer-url changed": {
			changedFlags: []string{"oidc-issuer-url"},
			want:         true,
		},
		"oidc-signing-algs changed": {
			changedFlags: []string{"oidc-signing-algs"},
			want:         true,
		},
		"non-oidc flag changed": {
			changedFlags: []string{"secure-port"},
			want:         false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().String("oidc-issuer-url", "", "")
			cmd.Flags().String("oidc-client-id", "", "")
			cmd.Flags().String("oidc-ca-file", "", "")
			cmd.Flags().String("oidc-username-claim", "", "")
			cmd.Flags().String("oidc-username-prefix", "", "")
			cmd.Flags().String("oidc-groups-claim", "", "")
			cmd.Flags().String("oidc-groups-prefix", "", "")
			cmd.Flags().StringSlice("oidc-signing-algs", nil, "")
			cmd.Flags().String("oidc-required-claim", "", "")
			cmd.Flags().String("secure-port", "", "")

			for _, name := range tc.changedFlags {
				if err := cmd.Flags().Set(name, "value"); err != nil {
					t.Fatalf("setting flag %q: %v", name, err)
				}
			}

			if got := oidcFlagsChanged(cmd); got != tc.want {
				t.Errorf("oidcFlagsChanged() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidate_MutualExclusivity(t *testing.T) {
	tests := map[string]struct {
		configFile    string
		changedFlags  []string
		wantErrSubstr string
	}{
		"both authentication-config and oidc-issuer-url is an error": {
			configFile:    "/some/path",
			changedFlags:  []string{"oidc-issuer-url"},
			wantErrSubstr: "mutually exclusive",
		},
		"both authentication-config and oidc-ca-file is an error": {
			configFile:    "/some/path",
			changedFlags:  []string{"oidc-ca-file"},
			wantErrSubstr: "mutually exclusive",
		},
		"authentication-config without oidc flags is not a mutual exclusivity error": {
			configFile: "/some/path",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o := New()
			cmd := &cobra.Command{}
			o.AddFlags(cmd)

			o.AuthenticationConfig.ConfigFile = tc.configFile
			for _, flagName := range tc.changedFlags {
				if err := cmd.Flags().Set(flagName, "https://issuer.example.com"); err != nil {
					t.Fatalf("setting flag %q: %v", flagName, err)
				}
			}

			err := o.Validate(cmd)
			if tc.wantErrSubstr == "" {
				if err != nil && strings.Contains(err.Error(), "mutually exclusive") {
					t.Errorf("Validate() unexpected mutual exclusivity error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tc.wantErrSubstr)
				}
			}
		})
	}
}
