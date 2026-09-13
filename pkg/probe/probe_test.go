// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"errors"
	"sync"
	"testing"

	"k8s.io/apiserver/pkg/authentication/authenticator"

	"github.com/heptiolabs/healthcheck"
)

// fakeAuther simulates the union authenticator: tokens listed in notInit
// hit an issuer whose JWKS is not yet fetched; every other token reaches
// an initialized issuer and fails ordinary verification.
type fakeAuther struct {
	mu      sync.Mutex
	notInit map[string]bool
	calls   map[string]int
}

func (f *fakeAuther) AuthenticateToken(_ context.Context, token string) (*authenticator.Response, bool, error) {
	f.mu.Lock()
	if f.calls == nil {
		f.calls = make(map[string]int)
	}
	f.calls[token]++
	f.mu.Unlock()

	if f.notInit[token] {
		return nil, false, errors.New("oidc: authenticator not initialized")
	}
	return nil, false, errors.New("oidc: verify token: signature invalid")
}

func (f *fakeAuther) callCount(token string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[token]
}

func newTestHealthCheck(requireAll bool, notInit map[string]bool, issuers ...IssuerReadiness) *HealthCheck {
	return &HealthCheck{
		handler:     healthcheck.NewHandler(),
		oidcAuther:  &fakeAuther{notInit: notInit},
		issuers:     issuers,
		requireAll:  requireAll,
		initialized: make(map[string]bool),
	}
}

func TestCheckReadiness(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}
	issuerB := IssuerReadiness{IssuerURL: "https://b.example.com", FakeJWT: "jwt-b"}

	tests := []struct {
		name       string
		requireAll bool
		notInit    map[string]bool
		wantReady  bool
	}{
		{
			name:       "default mode: one of two initialized is ready",
			requireAll: false,
			notInit:    map[string]bool{"jwt-b": true},
			wantReady:  true,
		},
		{
			name:       "default mode: none initialized is not ready",
			requireAll: false,
			notInit:    map[string]bool{"jwt-a": true, "jwt-b": true},
			wantReady:  false,
		},
		{
			name:       "require-all: one pending is not ready",
			requireAll: true,
			notInit:    map[string]bool{"jwt-b": true},
			wantReady:  false,
		},
		{
			name:       "require-all: all initialized is ready",
			requireAll: true,
			notInit:    map[string]bool{},
			wantReady:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHealthCheck(tc.requireAll, tc.notInit, issuerA, issuerB)
			err := h.Check()
			if tc.wantReady && err != nil {
				t.Fatalf("expected ready, got error: %v", err)
			}
			if !tc.wantReady && err == nil {
				t.Fatal("expected not ready, got nil error")
			}
		})
	}
}

func TestCheckReadinessIsSticky(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}
	notInit := map[string]bool{}
	h := newTestHealthCheck(false, notInit, issuerA)

	if err := h.Check(); err != nil {
		t.Fatalf("expected ready, got: %v", err)
	}

	// Simulate the issuer regressing to uninitialized: readiness must stick.
	notInit["jwt-a"] = true
	if err := h.Check(); err != nil {
		t.Fatalf("expected readiness to be sticky, got: %v", err)
	}
}

// TestCheckContinuesProbingPendingAfterLatch verifies that once readiness
// latches (default mode, one of two issuers initialized), subsequent Check
// calls still return nil AND still probe the still-pending issuer so it can
// transition to initialized and be logged, while the already-initialized
// issuer is not re-probed.
func TestCheckContinuesProbingPendingAfterLatch(t *testing.T) {
	issuerA := IssuerReadiness{IssuerURL: "https://a.example.com", FakeJWT: "jwt-a"}
	issuerB := IssuerReadiness{IssuerURL: "https://b.example.com", FakeJWT: "jwt-b"}

	notInit := map[string]bool{"jwt-b": true}
	h := newTestHealthCheck(false, notInit, issuerA, issuerB)
	fake := h.oidcAuther.(*fakeAuther)

	if err := h.Check(); err != nil {
		t.Fatalf("expected ready (issuer A initialized), got: %v", err)
	}
	if !h.ready.Load() {
		t.Fatal("expected readiness to have latched")
	}

	aCallsAfterFirst := fake.callCount("jwt-a")
	bCallsAfterFirst := fake.callCount("jwt-b")
	if aCallsAfterFirst != 1 || bCallsAfterFirst != 1 {
		t.Fatalf("expected 1 call each after first Check, got a=%d b=%d", aCallsAfterFirst, bCallsAfterFirst)
	}

	// Second Check: readiness already latched, so it must return nil
	// regardless of issuer B still being pending, but issuer B must still
	// be probed (call count increases) while issuer A (already
	// initialized) must not be re-probed.
	if err := h.Check(); err != nil {
		t.Fatalf("expected nil error once latched even with issuer B pending, got: %v", err)
	}

	if got := fake.callCount("jwt-a"); got != aCallsAfterFirst {
		t.Fatalf("expected initialized issuer A not to be re-probed, call count changed from %d to %d", aCallsAfterFirst, got)
	}
	if got := fake.callCount("jwt-b"); got <= bCallsAfterFirst {
		t.Fatalf("expected pending issuer B to still be probed, call count did not increase (still %d)", got)
	}

	// Now let issuer B initialize and confirm the transition is picked up
	// and it is subsequently no longer re-probed either.
	delete(notInit, "jwt-b")
	if err := h.Check(); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	bCallsAfterInit := fake.callCount("jwt-b")

	if err := h.Check(); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if got := fake.callCount("jwt-b"); got != bCallsAfterInit {
		t.Fatalf("expected issuer B not to be re-probed once initialized, call count changed from %d to %d", bCallsAfterInit, got)
	}
}
