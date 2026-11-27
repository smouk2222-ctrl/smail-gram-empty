package rpc

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/owpengram/owpengram-td/tg"

	appauth "telesrv/internal/app/auth"
	"telesrv/internal/domain"
	"telesrv/internal/store"
	"telesrv/internal/store/memory"
)

type dropTempTestSessions struct {
	SessionBinder
	closed [][8]byte
}

func (s *dropTempTestSessions) CloseSessionsForRawAuthKeyExcept(rawAuthKeyID [8]byte, exceptSessionID int64) int {
	s.closed = append(s.closed, rawAuthKeyID)
	return 1
}

func TestAuthDropTempAuthKeysPreservesCurrentAndExceptKeys(t *testing.T) {
	ctx := context.Background()
	keys := memory.NewAuthKeyStore()
	bindings := memory.NewTempAuthKeyBindingStore(keys)
	expiry := int(time.Now().Add(time.Hour).Unix())
	permID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	currentID := [8]byte{2, 3, 4, 5, 6, 7, 8, 9}
	keepID := [8]byte{3, 4, 5, 6, 7, 8, 9, 10}
	dropID := [8]byte{4, 5, 6, 7, 8, 9, 10, 11}
	permInt := int64(binary.LittleEndian.Uint64(permID[:]))

	for _, key := range []store.AuthKeyData{
		{ID: permID},
		{ID: currentID, ExpiresAt: expiry},
		{ID: keepID, ExpiresAt: expiry},
		{ID: dropID, ExpiresAt: expiry},
	} {
		if err := keys.Save(ctx, key); err != nil {
			t.Fatalf("save auth key %x: %v", key.ID, err)
		}
	}
	for _, id := range [][8]byte{currentID, keepID, dropID} {
		if err := bindings.Save(ctx, domain.TempAuthKeyBinding{
			TempAuthKeyID:    id,
			PermAuthKeyID:    permInt,
			ExpiresAt:        expiry,
			EncryptedMessage: []byte("proof"),
		}); err != nil {
			t.Fatalf("save binding %x: %v", id, err)
		}
	}

	svc := appauth.NewService(memory.NewUserStore(), memory.NewAuthorizationStore(), memory.NewCodeStore(), keys, bindings, "12345")
	sessions := &dropTempTestSessions{}
	r := &Router{deps: Deps{Auth: svc, Sessions: sessions}, tempKeyResolveCache: newTempKeyResolveCache(8)}
	cacheExpiry := time.Now().Add(time.Hour)
	for _, id := range [][8]byte{currentID, keepID, dropID} {
		r.tempKeyResolveCache.Store(id, permID, cacheExpiry, time.Now())
	}

	ctx = WithAuthKeyID(ctx, permID)
	ctx = WithRawAuthKeyID(ctx, currentID)
	ok, err := r.onAuthDropTempAuthKeys(ctx, &tg.AuthDropTempAuthKeysRequest{
		ExceptAuthKeys: []int64{int64(binary.LittleEndian.Uint64(keepID[:]))},
	})
	if err != nil || !ok {
		t.Fatalf("onAuthDropTempAuthKeys = %v, %v; want true, nil", ok, err)
	}
	if len(sessions.closed) != 1 || sessions.closed[0] != dropID {
		t.Fatalf("closed raw sessions = %x, want only %x", sessions.closed, dropID)
	}

	for _, tc := range []struct {
		id    [8]byte
		found bool
	}{
		{id: currentID, found: true},
		{id: keepID, found: true},
		{id: dropID, found: false},
	} {
		if _, found, err := keys.Get(ctx, tc.id); err != nil || found != tc.found {
			t.Fatalf("key %x found=%v err=%v, want found=%v", tc.id, found, err, tc.found)
		}
		if _, found := r.tempKeyResolveCache.GetResolved(tc.id, time.Now()); found != tc.found {
			t.Fatalf("cache key %x found=%v, want found=%v", tc.id, found, tc.found)
		}
	}
}
