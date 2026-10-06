// Copyright Jetstack Ltd. See LICENSE for details.
package multiprovider

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework"
	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework/helper"
)

const (
	secondIssuerName = "oidc-issuer-extra-e2e"
	secondClientID   = "kube-oidc-proxy-e2e-extra-client_id"
	authConfigName   = "auth-config"
	authConfigFile   = "config.yaml"
)

var _ = framework.CasesDescribe("Multi-Provider OIDC", func() {
	f := framework.NewDefaultFramework("multiprovider")

	It("should accept tokens from both primary and extra OIDC providers", func() {
		By("Deploying a second OIDC issuer")
		extraBundle, extraURL, err := f.Helper().DeployNamedIssuer(f.Namespace.Name, secondIssuerName)
		Expect(err).NotTo(HaveOccurred())

		By("Creating AuthenticationConfiguration ConfigMap for the extra provider")
		authConfigYAML := buildAuthConfig(extraURL, extraBundle.CertBytes, secondClientID)
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      authConfigName,
				Namespace: f.Namespace.Name,
			},
			Data: map[string]string{
				authConfigFile: authConfigYAML,
			},
		}
		_, err = f.KubeClientSet.CoreV1().ConfigMaps(f.Namespace.Name).Create(
			context.TODO(), cm, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Redeploying proxy with --authentication-config pointing to the ConfigMap")
		authConfigVolume := corev1.Volume{
			Name: authConfigName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: authConfigName,
					},
				},
			},
		}
		f.DeployProxyWith(
			[]corev1.Volume{authConfigVolume},
			fmt.Sprintf("--authentication-config=/%s/%s", authConfigName, authConfigFile),
		)

		// proxyConfig.Transport trusts the proxy TLS cert; reused for all requests below.
		proxyConfig := f.NewProxyRestConfig()

		By("Valid token from primary issuer should be forwarded by the proxy")
		primaryClient := f.NewProxyClient()
		_, err = primaryClient.CoreV1().Pods(f.Namespace.Name).List(context.TODO(), metav1.ListOptions{})
		// Forbidden from RBAC means authentication passed.
		if err != nil {
			Expect(err.Error()).To(ContainSubstring("forbidden"),
				"expected primary token to pass proxy authentication")
		}

		By("Valid token from extra provider should be forwarded by the proxy")
		extraPayload := f.Helper().NewTokenPayload(extraURL, secondClientID, time.Now().Add(time.Minute))
		extraToken, err := f.Helper().SignToken(extraBundle, extraPayload)
		Expect(err).NotTo(HaveOccurred())
		expectForwarded(f.Helper().NewRequester(proxyConfig.Transport, extraToken),
			proxyConfig.Host, f.Namespace.Name)

		By("Token from extra provider with wrong audience should be rejected")
		wrongAudPayload := f.Helper().NewTokenPayload(extraURL, "wrong-audience", time.Now().Add(time.Minute))
		wrongAudToken, err := f.Helper().SignToken(extraBundle, wrongAudPayload)
		Expect(err).NotTo(HaveOccurred())
		expectUnauthorized(f.Helper().NewRequester(proxyConfig.Transport, wrongAudToken),
			proxyConfig.Host, f.Namespace.Name)

		By("Expired token from extra provider should be rejected")
		expiredPayload := f.Helper().NewTokenPayload(extraURL, secondClientID, time.Now().Add(-time.Minute))
		expiredToken, err := f.Helper().SignToken(extraBundle, expiredPayload)
		Expect(err).NotTo(HaveOccurred())
		expectUnauthorized(f.Helper().NewRequester(proxyConfig.Transport, expiredToken),
			proxyConfig.Host, f.Namespace.Name)

		By("Token signed with untrusted key should be rejected")
		untrustedBundle, _, err := f.Helper().DeployNamedIssuer(f.Namespace.Name, "oidc-issuer-untrusted-e2e")
		Expect(err).NotTo(HaveOccurred())
		untrustedPayload := f.Helper().NewTokenPayload(extraURL, secondClientID, time.Now().Add(time.Minute))
		untrustedToken, err := f.Helper().SignToken(untrustedBundle, untrustedPayload)
		Expect(err).NotTo(HaveOccurred())
		expectUnauthorized(f.Helper().NewRequester(proxyConfig.Transport, untrustedToken),
			proxyConfig.Host, f.Namespace.Name)
	})
})

// buildAuthConfig constructs an AuthenticationConfiguration YAML for a single
// extra JWT provider with an inline PEM certificate authority.
func buildAuthConfig(issuerURL *url.URL, caCert []byte, clientID string) string {
	return fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: %s
    audiences: ["%s"]
    certificateAuthority: |
%s
  claimMappings:
    username:
      claim: email
      prefix: ""
    groups:
      claim: groups
      prefix: ""
`, issuerURL.String(), clientID, indentPEM(caCert))
}

// indentPEM indents each line of a PEM block by 6 spaces for YAML embedding.
func indentPEM(pem []byte) string {
	lines := bytes.Split(bytes.TrimRight(pem, "\n"), []byte("\n"))
	var out []byte
	for _, line := range lines {
		out = append(out, []byte("      ")...)
		out = append(out, line...)
		out = append(out, '\n')
	}
	return string(out)
}

// expectForwarded asserts the proxy forwarded the request (authentication passed).
// A Forbidden response from the API server is acceptable.
func expectForwarded(requester *helper.Requester, host, ns string) {
	target := fmt.Sprintf("%s/api/v1/namespaces/%s/pods", host, ns)
	body, resp, err := requester.Get(target)
	body = bytes.TrimSpace(body)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.StatusCode).NotTo(Equal(http.StatusUnauthorized),
		"expected proxy to forward request, got 401 body: %q", body)
}

// expectUnauthorized asserts the proxy rejected the request with 401.
func expectUnauthorized(requester *helper.Requester, host, ns string) {
	target := fmt.Sprintf("%s/api/v1/namespaces/%s/pods", host, ns)
	body, resp, err := requester.Get(target)
	body = bytes.TrimSpace(body)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized),
		"expected proxy to reject request, got body: %q", body)
}
