package postgres

import (
	"context"
	"testing"
	"time"

	"telesrv/internal/domain"
)

func TestTempAuthKeyBindingStoreDeleteByPermExceptPostgres(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	keys := NewAuthKeyStore(pool)
	bindings := NewTempAuthKeyBindingStore(pool)
	expiry := int(time.Now().Add(time.Hour).Unix())

	permID := saveTempIdentityTestAuthKey(t, ctx, pool, keys, 0)
	otherPermID := saveTempIdentityTestAuthKey(t, ctx, pool, keys, 0)
	keepID := saveTempIdentityTestAuthKey(t, ctx, pool, keys, expiry)
	dropID := saveTempIdentityTestAuthKey(t, ctx, pool, keys, expiry)
	otherTempID := saveTempIdentityTestAuthKey(t, ctx, pool, keys, expiry)
	unboundID := saveTempIdentityTestAuthKey(t, ctx, pool, keys, expiry)

	for _, binding := range []domain.TempAuthKeyBinding{
		{TempAuthKeyID: keepID, PermAuthKeyID: authKeyIDToInt64(permID), ExpiresAt: expiry, EncryptedMessage: []byte("keep")},
		{TempAuthKeyID: dropID, PermAuthKeyID: authKeyIDToInt64(permID), ExpiresAt: expiry, EncryptedMessage: []byte("drop")},
		{TempAuthKeyID: otherTempID, PermAuthKeyID: authKeyIDToInt64(otherPermID), ExpiresAt: expiry, EncryptedMessage: []byte("other")},
	} {
		if err := bindings.Save(ctx, binding); err != nil {
			t.Fatalf("save binding %x: %v", binding.TempAuthKeyID, err)
		}
	}

	removed, err := bindings.DeleteByPermExcept(ctx, authKeyIDToInt64(permID), []int64{authKeyIDToInt64(keepID)})
	if err != nil {
		t.Fatalf("DeleteByPermExcept: %v", err)
	}
	if len(removed) != 1 || removed[0] != dropID {
		t.Fatalf("removed keys = %x, want only %x", removed, dropID)
	}
	for _, tc := range []struct {
		id    [8]byte
		found bool
	}{
		{id: permID, found: true},
		{id: keepID, found: true},
		{id: dropID, found: false},
		{id: otherTempID, found: true},
		{id: unboundID, found: true},
	} {
		if _, found, err := keys.Get(ctx, tc.id); err != nil || found != tc.found {
			t.Fatalf("key %x found=%v err=%v, want found=%v", tc.id, found, err, tc.found)
		}
	}
	if _, found, err := bindings.GetByTemp(ctx, dropID); err != nil || found {
		t.Fatalf("dropped binding found=%v err=%v, want absent", found, err)
	}
	if _, found, err := bindings.GetByTemp(ctx, keepID); err != nil || !found {
		t.Fatalf("preserved binding found=%v err=%v, want present", found, err)
	}
}
