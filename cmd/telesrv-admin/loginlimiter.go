package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	adminLoginWindow       = 15 * time.Minute
	adminLoginPerIPLimit   = 20
	adminLoginPerUserLimit = 5
	adminLoginMaxBuckets   = 8192
)

type loginAttemptBucket struct {
	count int
	until time.Time
}

// loginAttemptLimiter is a fixed-window, process-local limiter. Its map is
// bounded so a flood of distinct source addresses/usernames cannot grow memory
// without limit. The source address comes from RemoteAddr; forwarded headers
// are deliberately ignored because this server has no trusted-proxy setting.
type loginAttemptLimiter struct {
	mu      sync.Mutex
	buckets map[string]loginAttemptBucket
}

func (l *loginAttemptLimiter) allow(remoteAddr, username string, now time.Time) (bool, time.Duration) {
	ip := remoteIP(remoteAddr)
	if ip == "" {
		ip = "unknown"
	}
	nameDigest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(username))))
	ipKey := "ip:" + ip
	userKey := "user:" + ip + ":" + hex.EncodeToString(nameDigest[:])

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.buckets == nil {
		l.buckets = make(map[string]loginAttemptBucket)
	}
	for key, bucket := range l.buckets {
		if !now.Before(bucket.until) {
			delete(l.buckets, key)
		}
	}

	ipBucket, ipExists := l.buckets[ipKey]
	userBucket, userExists := l.buckets[userKey]
	newBuckets := 0
	if !ipExists {
		newBuckets++
	}
	if !userExists {
		newBuckets++
	}
	if len(l.buckets)+newBuckets > adminLoginMaxBuckets {
		return false, adminLoginWindow
	}

	if !ipExists {
		ipBucket.until = now.Add(adminLoginWindow)
	}
	if !userExists {
		userBucket.until = now.Add(adminLoginWindow)
	}
	if ipBucket.count >= adminLoginPerIPLimit {
		return false, ipBucket.until.Sub(now)
	}

	// Count every attempt against the IP budget, including attempts that have
	// already exhausted the per-username budget. Rotating usernames therefore
	// cannot bypass the broader source-address ceiling.
	ipBucket.count++
	l.buckets[ipKey] = ipBucket

	if userBucket.count >= adminLoginPerUserLimit {
		return false, userBucket.until.Sub(now)
	}
	userBucket.count++
	l.buckets[userKey] = userBucket
	return true, 0
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(remoteAddr, "[]")
}
