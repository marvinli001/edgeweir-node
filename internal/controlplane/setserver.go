package controlplane

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/identity"
)

// SetServerResult is what SetServer did.
type SetServerResult struct {
	// The address before and after; Unchanged when addr was already the
	// identity's address (checked all the same).
	Previous  Address
	Current   Address
	Unchanged bool
	CheckResult
}

// SetServer checks addr with the identity in store (Check: the pinned CA
// and the identity's client certificate) and, when the check passes, makes
// it the identity's console address, keeping the previous one as the
// fallback. The identity, keys and certificate stay; nothing changes when
// the check fails. A running agent picks the address up on its own.
func SetServer(ctx context.Context, store identity.Store, addr Address) (SetServerResult, error) {
	id, err := store.Load()
	if err != nil {
		return SetServerResult{}, err
	}
	if now := time.Now(); now.After(id.Certificate.NotAfter) {
		return SetServerResult{}, fmt.Errorf("the certificate expired at %s; enroll again with a new token (enroll --force)",
			id.Certificate.NotAfter.UTC().Format(time.RFC3339))
	}
	res := SetServerResult{Previous: CurrentAddress(id.Identity), Current: addr}
	cert := id.TLS
	res.CheckResult, err = Check(ctx, id, func() *tls.Certificate { return &cert }, addr)
	if err != nil {
		return res, err
	}
	if addr.Equal(res.Previous) {
		res.Unchanged = true
		return res, nil
	}
	_, err = store.UpdateServer(id.Identity, func(next *identity.Identity) {
		next.FallbackServerURL, next.FallbackServerName = res.Previous.URL, res.Previous.ServerName
		next.ServerURL, next.ServerName = addr.URL, addr.ServerName
		next.ServerSource, next.ServerChangedAt = identity.ServerSourceCommand, time.Now().UTC().Truncate(time.Second)
	})
	return res, err
}
