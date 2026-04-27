// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	api "k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/apis/apiserver/install"
)

var (
	authConfigScheme = runtime.NewScheme()
	authConfigCodecs = serializer.NewCodecFactory(authConfigScheme, serializer.EnableStrict)
)

func init() {
	install.Install(authConfigScheme)
}

// LoadAuthenticationConfig reads a Kubernetes AuthenticationConfiguration YAML file
// (apiVersion: apiserver.config.k8s.io/v1beta1, kind: AuthenticationConfiguration)
// and returns the list of JWT authenticators defined in the jwt field.
func LoadAuthenticationConfig(configFile string) ([]api.JWTAuthenticator, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("reading authentication config: %w", err)
	}

	obj, err := runtime.Decode(authConfigCodecs.UniversalDecoder(), data)
	if err != nil {
		return nil, fmt.Errorf("parsing authentication config: %w", err)
	}

	config, ok := obj.(*api.AuthenticationConfiguration)
	if !ok {
		return nil, fmt.Errorf("expected AuthenticationConfiguration, got %T", obj)
	}

	if len(config.JWT) == 0 {
		return nil, fmt.Errorf("authentication config must contain at least one jwt authenticator")
	}

	return config.JWT, nil
}
