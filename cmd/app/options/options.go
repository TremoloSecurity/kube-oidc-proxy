// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	k8sErrors "k8s.io/apimachinery/pkg/util/errors"

	cliflag "k8s.io/component-base/cli/flag"
)

const (
	AppName = "kube-oidc-proxy"
)

type Options struct {
	App                  *KubeOIDCProxyOptions
	OIDCAuthentication   *OIDCAuthenticationOptions
	AuthenticationConfig *AuthenticationConfigOptions
	SecureServing        *SecureServingOptions
	Audit                *AuditOptions
	Client               *ClientOptions
	Misc                 *MiscOptions

	nfs *cliflag.NamedFlagSets
}

func New() *Options {
	nfs := new(cliflag.NamedFlagSets)

	// Add flags to command sets
	return &Options{
		App:                  NewKubeOIDCProxyOptions(nfs),
		OIDCAuthentication:   NewOIDCAuthenticationOptions(nfs),
		AuthenticationConfig: NewAuthenticationConfigOptions(nfs),
		SecureServing:        NewSecureServingOptions(nfs),
		Audit:                NewAuditOptions(nfs),
		Client:               NewClientOptions(nfs),
		Misc:                 NewMiscOptions(nfs),

		nfs: nfs,
	}
}

func (o *Options) AddFlags(cmd *cobra.Command) {
	// pretty output from kube-apiserver
	usageFmt := "Usage:\n  %s\n"
	cols, _, _ := term.GetSize(0)
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStderr(), *o.nfs, cols)
		return nil
	})

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStdout(), *o.nfs, cols)
	})

	fs := cmd.Flags()
	for _, f := range o.nfs.FlagSets {
		fs.AddFlagSet(f)
	}
}

func (o *Options) Validate(cmd *cobra.Command) error {
	if cmd.Flag("version").Value.String() == "true" {
		o.Misc.PrintVersionAndExit()
	}

	var errs []error

	if err := o.AuthenticationConfig.Validate(); err != nil {
		errs = append(errs, err)
	}

	authConfigSet := o.AuthenticationConfig.ConfigFile != ""

	if authConfigSet && oidcFlagsChanged(cmd) {
		errs = append(errs, fmt.Errorf("authentication-config and --oidc-* flags are mutually exclusive"))
	}

	if err := o.OIDCAuthentication.Validate(authConfigSet); err != nil {
		errs = append(errs, err)
	}

	if err := o.SecureServing.Validate(); len(err) > 0 {
		errs = append(errs, err...)
	}

	if o.SecureServing.BindPort == o.App.ReadinessProbePort {
		errs = append(errs, errors.New("unable to securely serve on port 8080 (used by readiness probe)"))
	}

	if err := o.Audit.Validate(); len(err) > 0 {
		errs = append(errs, err...)
	}

	if o.App.DisableImpersonation &&
		(o.App.ExtraHeaderOptions.EnableClientIPExtraUserHeader || len(o.App.ExtraHeaderOptions.ExtraUserHeaders) > 0) {
		errs = append(errs, errors.New("cannot add extra user headers when impersonation disabled"))
	}

	if len(errs) > 0 {
		return k8sErrors.NewAggregate(errs)
	}

	return nil
}

var oidcFlagNames = []string{
	"oidc-issuer-url",
	"oidc-client-id",
	"oidc-ca-file",
	"oidc-username-claim",
	"oidc-username-prefix",
	"oidc-groups-claim",
	"oidc-groups-prefix",
	"oidc-signing-algs",
	"oidc-required-claim",
}

func oidcFlagsChanged(cmd *cobra.Command) bool {
	for _, name := range oidcFlagNames {
		if f := cmd.Flag(name); f != nil && f.Changed {
			return true
		}
	}
	return false
}
