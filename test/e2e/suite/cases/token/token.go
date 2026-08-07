// Copyright Jetstack Ltd. See LICENSE for details.
package token

import (
	"github.com/jetstack/kube-oidc-proxy/test/e2e/framework"
	"github.com/jetstack/kube-oidc-proxy/test/e2e/suite/cases/sharedtests"
)

var _ = framework.CasesDescribe("Token", func() {
	f := framework.NewDefaultFramework("token")
	sharedtests.RunTokenValidationTests(f)
})
