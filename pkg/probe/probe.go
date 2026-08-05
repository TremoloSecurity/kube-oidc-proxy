// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/heptiolabs/healthcheck"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/klog/v2"
)

const (
	timeout = time.Second * 10
)

// IssuerReadiness pairs an issuer with the fake JWT used to probe whether
// its authenticator has completed JWKS initialization.
type IssuerReadiness struct {
	IssuerURL string
	FakeJWT   string
}

type HealthCheck struct {
	handler    healthcheck.Handler
	oidcAuther authenticator.Token
	issuers    []IssuerReadiness
	requireAll bool
	ready      atomic.Bool

	mu          sync.Mutex
	initialized map[string]bool
}

func Run(port string, issuers []IssuerReadiness, requireAll bool, oidcAuther authenticator.Token) error {
	h := &HealthCheck{
		handler:     healthcheck.NewHandler(),
		oidcAuther:  oidcAuther,
		issuers:     issuers,
		requireAll:  requireAll,
		initialized: make(map[string]bool),
	}

	h.handler.AddReadinessCheck("secure serving", h.Check)

	go func() {
		for {
			err := http.ListenAndServe(net.JoinHostPort("0.0.0.0", port), h.handler)
			if err != nil {
				klog.Errorf("ready probe listener failed: %s", err)
			}
			time.Sleep(5 * time.Second)
		}
	}()

	return nil
}

// Check probes every issuer that has not yet been observed as initialized,
// logs per-issuer transitions and any still-pending issuers, and reports
// readiness. Once readiness latches (via ready.Store(true)) it always
// returns nil, but probing and pending-issuer logging continue on every
// call so operators keep seeing progress for issuers that initialize late.
func (h *HealthCheck) Check() error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	h.mu.Lock()
	defer h.mu.Unlock()

	var pending []string
	for _, issuer := range h.issuers {
		if h.initialized[issuer.IssuerURL] {
			continue
		}

		_, _, err := h.oidcAuther.AuthenticateToken(ctx, issuer.FakeJWT)
		if err != nil && strings.HasSuffix(err.Error(), "authenticator not initialized") {
			pending = append(pending, issuer.IssuerURL)
			continue
		}

		h.initialized[issuer.IssuerURL] = true
		klog.Infof("OIDC issuer initialized: %s (%d/%d ready)", issuer.IssuerURL, len(h.initialized), len(h.issuers))
	}

	if len(pending) > 0 {
		klog.Infof("readiness: %d/%d OIDC issuers initialized, pending: %v",
			len(h.initialized), len(h.issuers), pending)
	}

	if h.ready.Load() {
		return nil
	}

	if h.requireAll && len(pending) > 0 {
		return errors.New("OIDC providers not yet initialized")
	}
	if !h.requireAll && len(h.initialized) == 0 {
		return errors.New("no OIDC provider initialized yet")
	}

	h.ready.Store(true)
	klog.V(4).Info("OIDC provider(s) initialized, marking ready.")
	return nil
}
