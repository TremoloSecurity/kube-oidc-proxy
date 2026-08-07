// Copyright Jetstack Ltd. See LICENSE for details.
package options

import "testing"

func TestOIDCAuthenticationOptions_Validate(t *testing.T) {
	tests := map[string]struct {
		issuerURL     string
		clientID      string
		authConfigSet bool
		wantErr       bool
	}{
		"both issuer URL and client ID set is valid": {
			issuerURL: "https://vault.example.com",
			clientID:  "my-client",
			wantErr:   false,
		},
		"neither issuer URL nor client ID set is valid": {
			wantErr: false,
		},
		"issuer URL without client ID is an error": {
			issuerURL: "https://vault.example.com",
			wantErr:   true,
		},
		"client ID without issuer URL is an error": {
			clientID: "my-client",
			wantErr:  true,
		},
		"missing flags are ignored when authentication-config is set": {
			issuerURL:     "",
			clientID:      "",
			authConfigSet: true,
			wantErr:       false,
		},
		"mismatched flags are ignored when authentication-config is set": {
			issuerURL:     "https://vault.example.com",
			clientID:      "",
			authConfigSet: true,
			wantErr:       false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o := &OIDCAuthenticationOptions{
				IssuerURL: tc.issuerURL,
				ClientID:  tc.clientID,
			}
			err := o.Validate(tc.authConfigSet)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
