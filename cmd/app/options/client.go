// Copyright Jetstack Ltd. See LICENSE for details.
package options

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cliflag "k8s.io/component-base/cli/flag"
)

type ClientOptions struct {
	*genericclioptions.ConfigFlags

	KubeClientQPS   float32
	KubeClientBurst int
}

func NewClientOptions(nfs *cliflag.NamedFlagSets) *ClientOptions {
	c := &ClientOptions{
		ConfigFlags: genericclioptions.NewConfigFlags(true),
	}

	// Disable unwanted options
	c.CacheDir = nil
	c.Impersonate = nil
	c.ImpersonateGroup = nil

	return c.AddFlags(nfs.FlagSet("Client"))
}

func (c *ClientOptions) AddFlags(fs *pflag.FlagSet) *ClientOptions {
	c.ConfigFlags.AddFlags(fs)

	// Extra flags
	fs.Float32Var(&c.KubeClientQPS, "kube-client-qps", c.KubeClientQPS, "Sets the QPS on the app "+
		"kubernetes client, this will configure throttling on requests sent to the apiserver "+
		"(If not set, it will use client default ones)")
	fs.IntVar(&c.KubeClientBurst, "kube-client-burst", c.KubeClientBurst, "Sets the burst on the app "+
		"kubernetes client, this will configure throttling on requests sent to the apiserver"+
		"(If not set, it will use client default ones)")

	return c
}

func (c *ClientOptions) ClientFlagsChanged(cmd *cobra.Command) bool {
	for _, f := range clientOptionFlags() {
		if ff := cmd.Flag(f); ff != nil && ff.Changed {
			return true
		}
	}

	return false
}

func clientOptionFlags() []string {
	return []string{"certificate-authority", "client-certificate", "client-key", "cluster",
		"context", "insecure-skip-tls-verify", "kubeconfig", "namespace",
		"request-timeout", "server", "token", "user",
	}
}
