// Copyright Jetstack Ltd. See LICENSE for details.
// Package sharedtests defines token-validation Ginkgo cases that must pass
// against any proxy deployment — OIDC-flags or AuthenticationConfiguration.
// Callers deploy the proxy in the desired mode, then register these cases.
package sharedtests

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework"
	"github.com/jetstack/kube-oidc-proxy/test/util"
)

// RunTokenValidationTests registers Ginkgo It blocks exercising the proxy's
// token-validation behaviour against the framework's primary issuer.
func RunTokenValidationTests(f *framework.Framework) {
	It("rejects a missing token", func() {
		expectUnauthorized(f, f.IssuerKeyBundle(), nil)
	})

	It("rejects a malformed token", func() {
		expectUnauthorized(f, f.IssuerKeyBundle(), []byte("bad token"))
	})

	It("rejects a token from an unknown issuer", func() {
		badURL, err := url.Parse("incorrect-issuer.io")
		Expect(err).NotTo(HaveOccurred())
		expectUnauthorized(f, f.IssuerKeyBundle(),
			f.Helper().NewTokenPayload(badURL, f.ClientID(), time.Now().Add(time.Minute)))
	})

	It("rejects a token with a wrong audience", func() {
		expectUnauthorized(f, f.IssuerKeyBundle(),
			f.Helper().NewTokenPayload(f.IssuerURL(), "wrong-aud", time.Now().Add(time.Minute)))
	})

	It("rejects an expired token", func() {
		expectUnauthorized(f, f.IssuerKeyBundle(),
			f.Helper().NewTokenPayload(f.IssuerURL(), f.ClientID(), time.Now()))
	})

	It("accepts a valid token from the primary issuer", func() {
		_, err := f.NewProxyClient().CoreV1().Pods(f.Namespace.Name).List(context.TODO(), metav1.ListOptions{})
		if !k8sErrors.IsForbidden(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})
}

// ExpectProxyAuthenticated signs payload with keyBundle and asserts the proxy
// did not reject the token. Downstream Kubernetes authorization is not
// asserted, so 403 counts as success.
func ExpectProxyAuthenticated(f *framework.Framework, keyBundle *util.KeyBundle, payload []byte) {
	_, resp := proxyGetPods(f, keyBundle, payload)
	Expect(resp.StatusCode).NotTo(Equal(http.StatusUnauthorized),
		"token should be authenticated by proxy (got %d)", resp.StatusCode)
}

func expectUnauthorized(f *framework.Framework, keyBundle *util.KeyBundle, payload []byte) {
	body, resp := proxyGetPods(f, keyBundle, payload)
	body = bytes.TrimSpace(body)
	if resp.StatusCode != http.StatusUnauthorized || !bytes.Equal(body, []byte("Unauthorized")) {
		Expect(fmt.Errorf("expected 401 Unauthorized, got %d %q",
			resp.StatusCode, body)).NotTo(HaveOccurred())
	}
}

func proxyGetPods(f *framework.Framework, keyBundle *util.KeyBundle, payload []byte) ([]byte, *http.Response) {
	signedToken, err := f.Helper().SignToken(keyBundle, payload)
	Expect(err).NotTo(HaveOccurred())

	proxyConfig := f.NewProxyRestConfig()
	target := fmt.Sprintf("%s/api/v1/namespaces/%s/pods", proxyConfig.Host, f.Namespace.Name)

	body, resp, err := f.Helper().NewRequester(proxyConfig.Transport, signedToken).Get(target)
	Expect(err).NotTo(HaveOccurred())
	return body, resp
}
