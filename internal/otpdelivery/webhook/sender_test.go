package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"telesrv/internal/otpdelivery"
)

const testWebhookSecret = "0123456789abcdef0123456789abcdef"

func TestDeliverSendsVersionedSignedRequest(t *testing.T) {
	secret := testWebhookSecret
	var got requestBody
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") != "otp_test_delivery" {
			t.Errorf("method/idempotency = %s/%q", r.Method, r.Header.Get("Idempotency-Key"))
		}
		timestamp := r.Header.Get("X-Telesrv-Timestamp")
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(timestamp + "."))
		_, _ = mac.Write(body)
		wantSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if r.Header.Get("X-Telesrv-Signature") != wantSignature {
			t.Errorf("signature = %q, want %q", r.Header.Get("X-Telesrv-Signature"), wantSignature)
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"accepted":true,"message_id":"provider-42"}`)
	}))
	defer server.Close()

	sender, err := New(Config{URL: server.URL, Secret: secret, Timeout: time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	expiresAt := time.Now().Add(5 * time.Minute).UTC()
	result, err := sender.Deliver(context.Background(), otpdelivery.Request{
		DeliveryID: "otp_test_delivery",
		Purpose:    otpdelivery.PurposeLoginEmail,
		Channel:    otpdelivery.ChannelEmail,
		Recipient:  "alice@example.test",
		Code:       "482913",
		ExpiresAt:  expiresAt,
		Locale:     "zh-CN",
	})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if result.ProviderMessageID != "provider-42" {
		t.Fatalf("message id = %q", result.ProviderMessageID)
	}
	if got.Version != protocolVersion || got.DeliveryID != "otp_test_delivery" ||
		got.Purpose != otpdelivery.PurposeLoginEmail || got.Channel != otpdelivery.ChannelEmail ||
		got.Recipient != "alice@example.test" || got.Code != "482913" || got.Locale != "zh-CN" || got.ExpiresIn < 298 {
		t.Fatalf("request = %+v", got)
	}
}

func TestNewRequiresStrongSecret(t *testing.T) {
	for _, secret := range []string{"", "short", "0123456789abcdef0123456789abcde"} {
		if _, err := New(Config{URL: "https://otp.example.test/v1/deliveries", Secret: secret}); err == nil {
			t.Fatalf("New accepted a weak secret of length %d", len(secret))
		}
	}
}

func TestNewRejectsRemoteHTTP(t *testing.T) {
	if _, err := New(Config{URL: "http://otp.example.test/v1/deliveries", Secret: testWebhookSecret}); err == nil {
		t.Fatal("New accepted a non-loopback HTTP OTP webhook endpoint")
	}
}

func TestDeliverExplicitRejectionIsDefinite(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"accepted":false,"error_code":"RATE_LIMITED","retryable":true}`)
	}))
	defer server.Close()
	sender, err := New(Config{URL: server.URL, Secret: testWebhookSecret})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = sender.Deliver(context.Background(), validRequest())
	var rejected *otpdelivery.RejectedError
	if !errors.As(err, &rejected) || rejected.StatusCode != http.StatusTooManyRequests || rejected.Code != "RATE_LIMITED" || !rejected.Retryable {
		t.Fatalf("rejection = %#v err=%v", rejected, err)
	}
	if errors.Is(err, otpdelivery.ErrOutcomeUnknown) {
		t.Fatalf("explicit rejection marked unknown: %v", err)
	}
}

func TestDeliverMalformedSuccessIsOutcomeUnknown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	sender, err := New(Config{URL: server.URL, Secret: testWebhookSecret})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = sender.Deliver(context.Background(), validRequest())
	if !errors.Is(err, otpdelivery.ErrOutcomeUnknown) {
		t.Fatalf("err = %v, want unknown outcome", err)
	}
}

func TestDeliverTransportFailureIsOutcomeUnknown(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection reset after write")
	})}
	sender, err := New(Config{URL: "https://otp.example.test/send", Secret: testWebhookSecret, Client: client})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = sender.Deliver(context.Background(), validRequest())
	if !errors.Is(err, otpdelivery.ErrOutcomeUnknown) || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("err = %v, want unknown transport outcome", err)
	}
}

func TestDeliverDoesNotFollowRedirect(t *testing.T) {
	targetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalled = true
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	sender, err := New(Config{URL: server.URL, Secret: testWebhookSecret})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = sender.Deliver(context.Background(), validRequest())
	var rejected *otpdelivery.RejectedError
	if !errors.As(err, &rejected) || rejected.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("err = %v, want redirect rejection", err)
	}
	if targetCalled {
		t.Fatal("redirect target received OTP")
	}
}

func TestDeliverDoesNotFollowRedirectWithCustomClient(t *testing.T) {
	targetCalled := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalled <- struct{}{}
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	client := &http.Client{Timeout: time.Second}
	sender, err := New(Config{URL: server.URL, Secret: testWebhookSecret, Client: client})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = sender.Deliver(context.Background(), validRequest())
	var rejected *otpdelivery.RejectedError
	if !errors.As(err, &rejected) || rejected.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("err = %v, want redirect rejection", err)
	}
	if client.CheckRedirect != nil {
		t.Fatal("New mutated the caller-owned HTTP client")
	}
	select {
	case <-targetCalled:
		t.Fatal("custom HTTP client followed redirect and forwarded OTP")
	default:
	}
}

func validRequest() otpdelivery.Request {
	return otpdelivery.Request{
		DeliveryID: "otp_valid",
		Purpose:    otpdelivery.PurposeLoginSMS,
		Channel:    otpdelivery.ChannelSMS,
		Recipient:  "15550001001",
		Code:       "12345",
		ExpiresAt:  time.Now().Add(time.Minute),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
