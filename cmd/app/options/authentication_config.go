// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apiserver "k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/apis/apiserver/install"
	"k8s.io/apiserver/pkg/apis/apiserver/validation"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	cliflag "k8s.io/component-base/cli/flag"
)

var (
	authConfigScheme = runtime.NewScheme()
	authConfigCodecs = serializer.NewCodecFactory(authConfigScheme, serializer.EnableStrict)
)

func init() {
	install.Install(authConfigScheme)
}

type AuthenticationConfigOptions struct {
	ConfigFile string
}

func NewAuthenticationConfigOptions(nfs *cliflag.NamedFlagSets) *AuthenticationConfigOptions {
	return new(AuthenticationConfigOptions).AddFlags(nfs.FlagSet("Authentication Config"))
}

func (o *AuthenticationConfigOptions) AddFlags(fs *pflag.FlagSet) *AuthenticationConfigOptions {
	fs.StringVar(&o.ConfigFile, "authentication-config", o.ConfigFile,
		"Path to a file containing an AuthenticationConfiguration "+
			"(apiserver.config.k8s.io/v1 or v1beta1) enabling multi-issuer OIDC "+
			"authentication. This flag is mutually exclusive with the --oidc-* flags.")
	return o
}

func (o *AuthenticationConfigOptions) Validate() error {
	if o.ConfigFile == "" {
		return nil
	}
	if _, err := os.Stat(o.ConfigFile); err != nil {
		return fmt.Errorf("authentication-config file %q: %w", o.ConfigFile, err)
	}
	return nil
}

// Load reads, strictly decodes (v1 or v1beta1), converts to the internal
// type and validates the whole AuthenticationConfiguration document.
// Validation compiles every CEL expression with the given compiler and
// rejects duplicate issuers across entries.
func (o *AuthenticationConfigOptions) Load(compiler authenticationcel.Compiler) (*apiserver.AuthenticationConfiguration, error) {
	data, err := os.ReadFile(o.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("reading authentication-config %q: %w", o.ConfigFile, err)
	}

	obj, gvk, err := authConfigCodecs.UniversalDecoder().Decode(data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing authentication-config %q: %w", o.ConfigFile, err)
	}

	cfg, ok := obj.(*apiserver.AuthenticationConfiguration)
	if !ok {
		return nil, fmt.Errorf("authentication-config %q: expected AuthenticationConfiguration, got %s", o.ConfigFile, gvk)
	}

	if cfg.Anonymous != nil {
		return nil, fmt.Errorf("authentication-config %q: the 'anonymous' section is not supported by kube-oidc-proxy", o.ConfigFile)
	}

	if len(cfg.JWT) == 0 {
		return nil, fmt.Errorf("authentication-config %q: jwt list must not be empty", o.ConfigFile)
	}

	// disallowedIssuers is nil: that parameter exists for kube-apiserver to
	// reserve its own service-account issuer, which does not apply to the proxy.
	if errs := validation.ValidateAuthenticationConfiguration(compiler, cfg, nil).ToAggregate(); errs != nil {
		return nil, fmt.Errorf("invalid authentication-config %q: %w", o.ConfigFile, errs)
	}

	return cfg, nil
}
