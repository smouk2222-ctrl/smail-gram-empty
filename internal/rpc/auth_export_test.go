package rpc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func TestExportAuthTokenRoundTrip(t *testing.T) {
	const userID = int64(1780243201)
	token := signExportAuthToken(userID)
	got, err := verifyExportAuthToken(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != userID {
		t.Fatalf("got userID %d, want %d", got, userID)
	}
	if _, err := verifyExportAuthToken(token); err == nil {
		t.Fatal("expected reused export auth token to fail")
	}
}

func TestExportAuthTokenRejectsTampering(t *testing.T) {
	token := signExportAuthToken(1780243201)
	token[0] ^= 0xFF
	if _, err := verifyExportAuthToken(token); err == nil {
		t.Fatal("expected tampered token to fail verification")
	}
}

func TestExportAuthTokenRejectsWrongLength(t *testing.T) {
	if _, err := verifyExportAuthToken([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected short token to fail verification")
	}
}

func TestExportAuthTokenRejectsExpired(t *testing.T) {
	// Build a token with an already-past expiry, signed the same way
	// signExportAuthToken does, to exercise the expiry check specifically
	// (as opposed to the HMAC check).
	payload := make([]byte, 16, 48)
	binary.BigEndian.PutUint64(payload[0:8], uint64(1780243201))
	binary.BigEndian.PutUint64(payload[8:16], uint64(time.Now().Add(-time.Minute).UnixNano()))
	mac := hmac.New(sha256.New, exportAuthSecret)
	mac.Write(payload)
	token := mac.Sum(payload)

	if _, err := verifyExportAuthToken(token); err == nil {
		t.Fatal("expected expired token to fail verification")
	}
}

func TestExportAuthTokenConcurrentImportConsumesOnce(t *testing.T) {
	token := signExportAuthToken(1780243202)

	const attempts = 32
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
	)
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			if _, err := verifyExportAuthToken(token); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("successful imports = %d, want exactly one", successes)
	}
}
