// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"encoding/json"
	"fmt"
	"os"
)

// ExtraOIDCProvider defines configuration for an additional OIDC issuer
// accepted by the proxy alongside the primary --oidc-issuer-url.
type ExtraOIDCProvider struct {
	IssuerURL string   `json:"issuerUrl"`
	Audiences []string `json:"audiences"`

	// Username mapping: set Claim OR Expression (mutually exclusive).
	// At least one must be provided.
	UsernameClaim      string `json:"usernameClaim,omitempty"`
	UsernameExpression string `json:"usernameExpression,omitempty"`
	UsernamePrefix     string `json:"usernamePrefix,omitempty"`

	// Groups mapping: set Claim OR Expression (mutually exclusive).
	// Both are optional.
	GroupsClaim      string `json:"groupsClaim,omitempty"`
	GroupsExpression string `json:"groupsExpression,omitempty"`
	GroupsPrefix     string `json:"groupsPrefix,omitempty"`

	// CAFile is an optional path to a PEM-encoded CA certificate for this
	// provider. Falls back to the host root CAs when empty.
	CAFile string `json:"caFile,omitempty"`
}

// LoadExtraProviders reads a JSON file and returns the parsed provider list.
func LoadExtraProviders(configFile string) ([]ExtraOIDCProvider, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("reading extra providers config: %w", err)
	}

	var providers []ExtraOIDCProvider
	if err := json.Unmarshal(data, &providers); err != nil {
		return nil, fmt.Errorf("parsing extra providers config: %w", err)
	}

	for i, p := range providers {
		if p.IssuerURL == "" {
			return nil, fmt.Errorf("extra provider[%d]: issuerUrl is required", i)
		}
		if len(p.Audiences) == 0 {
			return nil, fmt.Errorf("extra provider[%d]: audiences must not be empty", i)
		}
		if p.UsernameClaim == "" && p.UsernameExpression == "" {
			return nil, fmt.Errorf("extra provider[%d]: one of usernameClaim or usernameExpression is required", i)
		}
		if p.UsernameClaim != "" && p.UsernameExpression != "" {
			return nil, fmt.Errorf("extra provider[%d]: usernameClaim and usernameExpression are mutually exclusive", i)
		}
		if p.GroupsClaim != "" && p.GroupsExpression != "" {
			return nil, fmt.Errorf("extra provider[%d]: groupsClaim and groupsExpression are mutually exclusive", i)
		}
	}

	return providers, nil
}
