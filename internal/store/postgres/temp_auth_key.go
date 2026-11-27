package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"telesrv/internal/domain"
	"telesrv/internal/store"
	"telesrv/internal/store/postgres/sqlcgen"
)

// TempAuthKeyBindingStore 用 PostgreSQL 实现 store.TempAuthKeyBindingStore。
type TempAuthKeyBindingStore struct {
	db sqlcgen.DBTX
	q  *sqlcgen.Queries
}

// NewTempAuthKeyBindingStore 基于 pgx 连接池（或事务）创建 TempAuthKeyBindingStore。
func NewTempAuthKeyBindingStore(db sqlcgen.DBTX) *TempAuthKeyBindingStore {
	return &TempAuthKeyBindingStore{db: db, q: sqlcgen.New(db)}
}

func (s *TempAuthKeyBindingStore) Save(ctx context.Context, b domain.TempAuthKeyBinding) error {
	_, err := s.SaveWithState(ctx, b)
	return err
}

func (s *TempAuthKeyBindingStore) SaveWithState(ctx context.Context, b domain.TempAuthKeyBinding) (domain.TempAuthKeyBindingResult, error) {
	if b.ExpiresAt <= 0 || int64(b.ExpiresAt) > math.MaxInt32 {
		return domain.TempAuthKeyBindingResult{}, store.ErrAuthKeyBindingInvalid
	}
	var result domain.TempAuthKeyBindingResult
	err := withAuthIdentityTx(ctx, s.db, "save temp auth key binding", func(tx pgx.Tx) error {
		var err error
		result, err = s.saveTx(ctx, tx, b)
		return err
	})
	return result, err
}

func (s *TempAuthKeyBindingStore) saveTx(ctx context.Context, tx pgx.Tx, b domain.TempAuthKeyBinding) (domain.TempAuthKeyBindingResult, error) {
	rawID := authKeyIDToInt64(b.TempAuthKeyID)
	var (
		status        string
		mergedLayer   int
		observationID int64
	)
	err := tx.QueryRow(ctx, `
/* temp_auth_key_bind_atomic */
SELECT bind_status, merged_layer, merged_observation_id
FROM public.telesrv_bind_temp_auth_key($1, $2, $3, $4, $5, $6)
`,
		rawID,
		b.PermAuthKeyID,
		b.Nonce,
		b.TempSessionID,
		b.ExpiresAt,
		b.EncryptedMessage,
	).Scan(&status, &mergedLayer, &observationID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return domain.TempAuthKeyBindingResult{}, store.ErrAuthKeyBindingInvalid
		}
		return domain.TempAuthKeyBindingResult{}, fmt.Errorf("bind temporary auth key atomically: %w", err)
	}
	switch status {
	case "ok":
		if mergedLayer < 0 || observationID < 0 || (observationID > 0 && mergedLayer == 0) {
			return domain.TempAuthKeyBindingResult{}, fmt.Errorf(
				"bind temporary auth key atomically: invalid result layer=%d observation=%d",
				mergedLayer, observationID,
			)
		}
		return domain.TempAuthKeyBindingResult{Layer: mergedLayer, LayerObservationID: observationID}, nil
	case "already_bound":
		return domain.TempAuthKeyBindingResult{}, store.ErrTempAuthKeyAlreadyBound
	case "binding_invalid":
		return domain.TempAuthKeyBindingResult{}, store.ErrAuthKeyBindingInvalid
	case "layer_invalid":
		return domain.TempAuthKeyBindingResult{}, store.ErrAuthKeySessionLayerInvalid
	case "layer_conflict":
		return domain.TempAuthKeyBindingResult{}, store.ErrAuthKeySessionLayerConflict
	default:
		return domain.TempAuthKeyBindingResult{}, fmt.Errorf("bind temporary auth key atomically: unknown status %q", status)
	}
}

// DeleteExpired 实现 store.TempAuthKeyBindingStore：按 auth_keys.expires_at 的部分索引
// 有界删除所有过期 temp key（含从未绑定的握手 key），binding 经 CASCADE 一并清除。
// Edge 已在准确协议时刻停止使用 key；这里的 24h 宽限只控制数据库物理回收。
func (s *TempAuthKeyBindingStore) DeleteExpired(ctx context.Context, expiredBefore int64, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	if expiredBefore <= 0 || expiredBefore > math.MaxInt32 {
		return 0, fmt.Errorf("delete expired temp auth keys: invalid expiry cutoff %d", expiredBefore)
	}
	n, err := s.q.DeleteExpiredTempAuthKeys(ctx, sqlcgen.DeleteExpiredTempAuthKeysParams{
		ExpiresAt: int32(expiredBefore),
		Limit:     int32(limit),
	})
	if err != nil {
		return 0, fmt.Errorf("delete expired temp auth keys: %w", err)
	}
	return int(n), nil
}

// DeleteByPermExcept removes the bound temporary keys for one permanent identity.
// The identity advisory lock serializes this operation with bind/rebind and direct
// auth-key deletion. All raw temp rows are locked in key order before the permanent
// row, matching the repository-wide identity -> raw temp -> permanent lock order.
func (s *TempAuthKeyBindingStore) DeleteByPermExcept(ctx context.Context, permAuthKeyID int64, exceptAuthKeyIDs []int64) ([][8]byte, error) {
	if permAuthKeyID == 0 {
		return nil, store.ErrAuthKeyBindingInvalid
	}
	exceptIDs := append([]int64{}, exceptAuthKeyIDs...)
	var deletedIDs []int64
	err := withAuthIdentityTx(ctx, s.db, "drop temporary auth keys", func(tx pgx.Tx) error {
		if err := lockPermanentAuthIdentities(ctx, tx, []int64{permAuthKeyID}); err != nil {
			return err
		}

		rows, err := tx.Query(ctx, `
SELECT binding.temp_auth_key_id
FROM public.temp_auth_key_bindings AS binding
JOIN public.auth_keys AS temp_key
  ON temp_key.auth_key_id = binding.temp_auth_key_id
WHERE binding.perm_auth_key_id = $1
  AND temp_key.expires_at > 0
  AND NOT (binding.temp_auth_key_id = ANY($2::bigint[]))
ORDER BY binding.temp_auth_key_id
`, permAuthKeyID, exceptIDs)
		if err != nil {
			return fmt.Errorf("list bound temporary auth keys: %w", err)
		}
		candidateIDs := make([]int64, 0)
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return fmt.Errorf("scan bound temporary auth key: %w", err)
			}
			candidateIDs = append(candidateIDs, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate bound temporary auth keys: %w", err)
		}
		rows.Close()

		lockedIDs := make([]int64, 0, len(candidateIDs))
		if len(candidateIDs) > 0 {
			rows, err = tx.Query(ctx, `
SELECT auth_key_id
FROM public.auth_keys
WHERE auth_key_id = ANY($1::bigint[])
ORDER BY auth_key_id
FOR UPDATE
`, candidateIDs)
			if err != nil {
				return fmt.Errorf("lock bound temporary auth keys: %w", err)
			}
			for rows.Next() {
				var id int64
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return fmt.Errorf("scan locked temporary auth key: %w", err)
				}
				lockedIDs = append(lockedIDs, id)
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				return fmt.Errorf("iterate locked temporary auth keys: %w", err)
			}
			rows.Close()
		}

		var permExpiry int
		err = tx.QueryRow(ctx, `
SELECT expires_at
FROM public.auth_keys
WHERE auth_key_id = $1
FOR UPDATE
`, permAuthKeyID).Scan(&permExpiry)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrAuthKeyNotFound
		}
		if err != nil {
			return fmt.Errorf("lock permanent auth key: %w", err)
		}
		if permExpiry != 0 {
			return store.ErrAuthKeyBindingInvalid
		}
		if len(lockedIDs) == 0 {
			return nil
		}

		// Revalidate the relation after locking the raw rows. The identity gate
		// prevents a concurrent bind from changing the parent; the recheck also
		// tolerates the independent bounded expired-key collector winning a row
		// lock before this transaction.
		rows, err = tx.Query(ctx, `
SELECT binding.temp_auth_key_id
FROM public.temp_auth_key_bindings AS binding
JOIN public.auth_keys AS temp_key
  ON temp_key.auth_key_id = binding.temp_auth_key_id
WHERE binding.perm_auth_key_id = $1
  AND temp_key.expires_at > 0
  AND binding.temp_auth_key_id = ANY($2::bigint[])
  AND NOT (binding.temp_auth_key_id = ANY($3::bigint[]))
ORDER BY binding.temp_auth_key_id
`, permAuthKeyID, lockedIDs, exceptIDs)
		if err != nil {
			return fmt.Errorf("revalidate bound temporary auth keys: %w", err)
		}
		actualIDs := make([]int64, 0, len(lockedIDs))
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return fmt.Errorf("scan revalidated temporary auth key: %w", err)
			}
			actualIDs = append(actualIDs, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate revalidated temporary auth keys: %w", err)
		}
		rows.Close()
		if len(actualIDs) == 0 {
			return nil
		}

		if _, err := tx.Exec(ctx, `
DELETE FROM public.update_states
WHERE auth_key_id = ANY($1::bigint[])
`, actualIDs); err != nil {
			return fmt.Errorf("delete temporary auth key update states: %w", err)
		}
		rows, err = tx.Query(ctx, `
DELETE FROM public.auth_keys
WHERE auth_key_id = ANY($1::bigint[])
RETURNING auth_key_id
`, actualIDs)
		if err != nil {
			return fmt.Errorf("delete temporary auth keys: %w", err)
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return fmt.Errorf("scan deleted temporary auth key: %w", err)
			}
			deletedIDs = append(deletedIDs, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate deleted temporary auth keys: %w", err)
		}
		rows.Close()
		sort.Slice(deletedIDs, func(i, j int) bool { return deletedIDs[i] < deletedIDs[j] })
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("drop temporary auth keys: %w", err)
	}
	removed := make([][8]byte, len(deletedIDs))
	for i, id := range deletedIDs {
		removed[i] = authKeyIDFromInt64(id)
	}
	return removed, nil
}

func (s *TempAuthKeyBindingStore) GetByTemp(ctx context.Context, tempAuthKeyID [8]byte) (domain.TempAuthKeyBinding, bool, error) {
	row, err := s.q.GetTempAuthKeyBinding(ctx, authKeyIDToInt64(tempAuthKeyID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.TempAuthKeyBinding{}, false, nil
		}
		return domain.TempAuthKeyBinding{}, false, fmt.Errorf("get temp auth key binding: %w", err)
	}
	return domain.TempAuthKeyBinding{
		TempAuthKeyID:    authKeyIDFromInt64(row.TempAuthKeyID),
		PermAuthKeyID:    row.PermAuthKeyID,
		Nonce:            row.Nonce,
		TempSessionID:    row.TempSessionID,
		ExpiresAt:        int(row.ExpiresAt),
		EncryptedMessage: append([]byte(nil), row.EncryptedMessage...),
	}, true, nil
}
