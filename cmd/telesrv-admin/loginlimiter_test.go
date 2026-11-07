package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoginAttemptLimiterEnforcesUsernameAndIPBudgets(t *testing.T) {
	var limiter loginAttemptLimiter
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

	for i := 0; i < adminLoginPerUserLimit; i++ {
		if ok, wait := limiter.allow("192.0.2.10:1000", "operator", now); !ok || wait != 0 {
			t.Fatalf("attempt %d unexpectedly denied: wait=%s", i+1, wait)
		}
	}
	if ok, wait := limiter.allow("192.0.2.10:2000", "OPERATOR", now); ok || wait <= 0 {
		t.Fatalf("sixth attempt for same IP/username = (%v, %s), want denied with retry delay", ok, wait)
	}

	// Different usernames and source ports still share the same IP budget.
	for i := adminLoginPerUserLimit; i < adminLoginPerIPLimit; i++ {
		if ok, wait := limiter.allow("192.0.2.10:3000", "other-"+string(rune('a'+i)), now); !ok || wait != 0 {
			t.Fatalf("IP attempt %d unexpectedly denied: wait=%s", i+1, wait)
		}
	}
	if ok, wait := limiter.allow("192.0.2.10:4000", "another-user", now); ok || wait <= 0 {
		t.Fatalf("attempt over IP budget = (%v, %s), want denied", ok, wait)
	}
}

func TestLoginAttemptLimiterResetsAfterWindow(t *testing.T) {
	var limiter loginAttemptLimiter
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	for i := 0; i < adminLoginPerUserLimit; i++ {
		if ok, _ := limiter.allow("192.0.2.20:1000", "operator", now); !ok {
			t.Fatalf("attempt %d unexpectedly denied", i+1)
		}
	}
	if ok, _ := limiter.allow("192.0.2.20:1000", "operator", now.Add(adminLoginWindow)); !ok {
		t.Fatal("attempt was not allowed after the fixed window expired")
	}
}

func TestRemoteIPUsesOnlyRemoteAddress(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/login", nil)
	req.RemoteAddr = "198.51.100.9:4567"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	if got := remoteIP(req.RemoteAddr); got != "198.51.100.9" {
		t.Fatalf("remoteIP = %q, want RemoteAddr host", got)
	}
}
