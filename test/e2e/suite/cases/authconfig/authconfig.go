// Copyright Jetstack Ltd. See LICENSE for details.
package authconfig

import (
	"context"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"sigs.k8s.io/yaml"

	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework"
	"github.com/jetstack/kube-oidc-proxy/test/e2e/suite/cases/sharedtests"
	"github.com/jetstack/kube-oidc-proxy/test/util"
)

const (
	issuer2Name      = "oidc-issuer2-e2e"
	authConfigVolume = "auth-config"
	authConfigKey    = "config.yaml"
)

var _ = framework.CasesDescribe("AuthenticationConfiguration multi-issuer", func() {
	f := framework.NewDefaultFramework("authconfig")

	var (
		issuer2Bundle *util.KeyBundle
		issuer2URL    *url.URL
	)

	f.BeforeProxyDeploy = func() {
		var err error

		By("Deploying second OIDC issuer")
		issuer2Bundle, issuer2URL, err = f.Helper().DeployNamedIssuer(f.Namespace.Name, issuer2Name)
		Expect(err).NotTo(HaveOccurred())

		By("Creating AuthenticationConfiguration ConfigMap")
		cfgYAML, err := yaml.Marshal(authConfig(
			jwtAuthenticator(f.IssuerURL().String(), f.ClientID(), f.IssuerKeyBundle().CertBytes),
			jwtAuthenticator(issuer2URL.String(), f.ClientID(), issuer2Bundle.CertBytes),
		))
		Expect(err).NotTo(HaveOccurred())

		_, err = f.KubeClientSet.CoreV1().ConfigMaps(f.Namespace.Name).Create(
			context.TODO(),
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: authConfigVolume},
				Data:       map[string]string{authConfigKey: string(cfgYAML)},
			},
			metav1.CreateOptions{},
		)
		Expect(err).NotTo(HaveOccurred())

		f.ExtraProxyVolumes = []corev1.Volume{configMapVolume(authConfigVolume)}
		f.ExtraProxyArgs = []string{"--authentication-config=/" + authConfigVolume + "/" + authConfigKey}
	}

	sharedtests.RunTokenValidationTests(f)

	It("accepts a valid token from the second configured issuer", func() {
		payload := f.Helper().NewTokenPayload(issuer2URL, f.ClientID(), time.Now().Add(time.Minute))
		sharedtests.ExpectProxyAuthenticated(f, issuer2Bundle, payload)
	})
})

func authConfig(jwts ...apiserverv1.JWTAuthenticator) apiserverv1.AuthenticationConfiguration {
	return apiserverv1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apiserver.config.k8s.io/v1",
			Kind:       "AuthenticationConfiguration",
		},
		JWT: jwts,
	}
}

func jwtAuthenticator(issuerURL, audience string, caBundle []byte) apiserverv1.JWTAuthenticator {
	emptyPrefix := ""
	return apiserverv1.JWTAuthenticator{
		Issuer: apiserverv1.Issuer{
			URL:                  issuerURL,
			Audiences:            []string{audience},
			CertificateAuthority: string(caBundle),
		},
		ClaimMappings: apiserverv1.ClaimMappings{
			Username: apiserverv1.PrefixedClaimOrExpression{Claim: "email", Prefix: &emptyPrefix},
			Groups:   apiserverv1.PrefixedClaimOrExpression{Claim: "groups", Prefix: &emptyPrefix},
		},
	}
}

func configMapVolume(name string) corev1.Volume {
	return corev1.Volume{
		Name: name,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: name},
			},
		},
	}
}
