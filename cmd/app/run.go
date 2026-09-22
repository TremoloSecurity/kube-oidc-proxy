// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	apiserverapi "k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	tokenunion "k8s.io/apiserver/pkg/authentication/token/union"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/jetstack/kube-oidc-proxy/cmd/app/options"
	"github.com/jetstack/kube-oidc-proxy/pkg/probe"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
	"github.com/jetstack/kube-oidc-proxy/pkg/proxy/tokenreview"
	"github.com/jetstack/kube-oidc-proxy/pkg/util"
)

func NewRunCommand(stopCh <-chan struct{}) *cobra.Command {
	// Build options
	opts := options.New()

	// Build command
	cmd := buildRunCommand(stopCh, opts)

	// Add option flags to command
	opts.AddFlags(cmd)

	return cmd
}

// Proxy command
func buildRunCommand(stopCh <-chan struct{}, opts *options.Options) *cobra.Command {
	return &cobra.Command{
		Use:  options.AppName,
		Long: "kube-oidc-proxy is a reverse proxy to authenticate users to Kubernetes API servers with Open ID Connect Authentication.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(cmd); err != nil {
				return err
			}

			// Here we determine to either use custom or 'in-cluster' client configuration
			var err error
			var restConfig *rest.Config
			if opts.Client.ClientFlagsChanged(cmd) {
				// One or more client flags have been set to use client flag built
				// config
				restConfig, err = opts.Client.ToRESTConfig()
				if err != nil {
					return err
				}

			} else {
				// No client flags have been set so default to in-cluster config
				restConfig, err = rest.InClusterConfig()
				if err != nil {
					return err
				}
			}

			// Set client throttling settings for Kubernetes clients.
			if opts.Client.KubeClientBurst > 0 {
				restConfig.Burst = opts.Client.KubeClientBurst
			}
			if opts.Client.KubeClientQPS > 0 {
				restConfig.QPS = opts.Client.KubeClientQPS
			}

			// Initialise token reviewer if enabled
			var tokenReviewer *tokenreview.TokenReview
			if opts.App.TokenPassthrough.Enabled {
				tokenReviewer, err = tokenreview.New(restConfig, opts.App.TokenPassthrough.Audiences)
				if err != nil {
					return err
				}
			}

			// Initialise Secure Serving Config
			secureServingInfo := new(server.SecureServingInfo)
			if err := opts.SecureServing.ApplyTo(&secureServingInfo); err != nil {
				return err
			}

			proxyConfig := &proxy.Config{
				TokenReview:          opts.App.TokenPassthrough.Enabled,
				DisableImpersonation: opts.App.DisableImpersonation,

				FlushInterval:   opts.App.FlushInterval,
				ExternalAddress: opts.SecureServing.BindAddress.String(),

				ExtraUserHeaders:                opts.App.ExtraHeaderOptions.ExtraUserHeaders,
				ExtraUserHeadersClientIPEnabled: opts.App.ExtraHeaderOptions.EnableClientIPExtraUserHeader,
			}

			// Setup Subject Access Review
			kubeclient, err := kubernetes.NewForConfig(restConfig)
			if err != nil {
				return err
			}

			subectAccessReviewer, err := subjectaccessreview.New(kubeclient.AuthorizationV1().SubjectAccessReviews())
			if err != nil {
				return err
			}

			tokenAuther, issuerURLs, err := buildTokenAuther(opts)
			if err != nil {
				return err
			}

			// Initialise proxy with token authenticator
			p, err := proxy.New(restConfig, tokenAuther, opts.Audit,
				tokenReviewer, subectAccessReviewer, secureServingInfo, proxyConfig)
			if err != nil {
				return err
			}

			// Build a per-issuer readiness probe entry.
			issuerProbes := make([]probe.IssuerReadiness, 0, len(issuerURLs))
			for _, issuerURL := range issuerURLs {
				fakeJWT, err := util.FakeJWT(issuerURL)
				if err != nil {
					return err
				}
				issuerProbes = append(issuerProbes, probe.IssuerReadiness{
					IssuerURL: issuerURL,
					FakeJWT:   fakeJWT,
				})
			}

			// Start readiness probe
			if err := probe.Run(strconv.Itoa(opts.App.ReadinessProbePort),
				issuerProbes, opts.App.ReadinessRequireAllIssuers,
				p.OIDCTokenAuthenticator()); err != nil {
				return err
			}

			// Run proxy
			waitCh, listenerStoppedCh, err := p.Run(stopCh)
			if err != nil {
				return err
			}

			<-waitCh
			<-listenerStoppedCh

			if err := p.RunPreShutdownHooks(); err != nil {
				return err
			}

			return nil
		},
	}
}

// caFromFile implements oidc.CAContentProvider backed by a PEM file.
type caFromFile struct {
	path string
}

func (c caFromFile) CurrentCABundleContent() []byte {
	data, err := os.ReadFile(c.path)
	if err != nil {
		klog.Errorf("failed to read CA file %q: %v", c.path, err)
	}
	return data
}

// caContentProvider returns the CAContentProvider to use for a given path.
// When path is empty it returns nil, signalling oidc.New() to use the system certificate pool.
func caContentProvider(path string) oidc.CAContentProvider {
	if path == "" {
		return nil
	}
	return caFromFile{path: path}
}

func buildTokenAuther(opts *options.Options) (authenticator.Token, []string, error) {
	if opts.AuthenticationConfig.ConfigFile != "" {
		return buildUnionAuther(opts)
	}
	return buildSingleAuther(opts.OIDCAuthentication)
}

func buildSingleAuther(o *options.OIDCAuthenticationOptions) (authenticator.Token, []string, error) {
	usernamePrefix := o.UsernamePrefix
	groupsPrefix := o.GroupsPrefix
	jwtConfig := apiserverapi.JWTAuthenticator{
		Issuer: apiserverapi.Issuer{
			URL:       o.IssuerURL,
			Audiences: []string{o.ClientID},
		},
		ClaimMappings: apiserverapi.ClaimMappings{
			Username: apiserverapi.PrefixedClaimOrExpression{
				Claim:  o.UsernameClaim,
				Prefix: &usernamePrefix,
			},
			Groups: apiserverapi.PrefixedClaimOrExpression{
				Claim:  o.GroupsClaim,
				Prefix: &groupsPrefix,
			},
		},
	}
	auther, err := oidc.New(context.Background(), oidc.Options{
		CAContentProvider:    caContentProvider(o.CAFile),
		SupportedSigningAlgs: o.SigningAlgs,
		JWTAuthenticator:     jwtConfig,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating OIDC authenticator for issuer %q: %w", o.IssuerURL, err)
	}
	return auther, []string{o.IssuerURL}, nil
}

func buildUnionAuther(opts *options.Options) (authenticator.Token, []string, error) {
	// One CEL compiler shared by document validation and every authenticator:
	// CEL environments are expensive to construct.
	compiler := authenticationcel.NewDefaultCompiler()

	authCfg, err := opts.AuthenticationConfig.Load(compiler)
	if err != nil {
		return nil, nil, err
	}

	authers := make([]authenticator.Token, 0, len(authCfg.JWT))
	issuerURLs := make([]string, 0, len(authCfg.JWT))
	for _, jwtEntry := range authCfg.JWT {
		auther, err := oidcAutherFromJWT(jwtEntry, compiler, oidc.AllValidSigningAlgorithms())
		if err != nil {
			return nil, nil, fmt.Errorf("building authenticator for issuer %q: %w", jwtEntry.Issuer.URL, err)
		}
		authers = append(authers, auther)
		issuerURLs = append(issuerURLs, jwtEntry.Issuer.URL)
	}

	klog.Infof("configured OIDC issuers: %v", issuerURLs)

	return tokenunion.NewFailOnError(authers...), issuerURLs, nil
}

func oidcAutherFromJWT(jwtConfig apiserverapi.JWTAuthenticator, compiler authenticationcel.Compiler, signingAlgs []string) (authenticator.Token, error) {
	var provider oidc.CAContentProvider
	if jwtConfig.Issuer.CertificateAuthority != "" {
		var err error
		provider, err = dynamiccertificates.NewStaticCAContent("oidc-authenticator", []byte(jwtConfig.Issuer.CertificateAuthority))
		if err != nil {
			return nil, fmt.Errorf("invalid certificateAuthority for issuer %q: %w", jwtConfig.Issuer.URL, err)
		}
	}

	return oidc.New(context.Background(), oidc.Options{
		CAContentProvider:    provider,
		SupportedSigningAlgs: signingAlgs,
		JWTAuthenticator:     jwtConfig,
		Compiler:             compiler,
	})
}
