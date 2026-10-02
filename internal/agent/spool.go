package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/fsutil"
)

// A spool keeps the batches of one report (statistics in
// traffic-spool.json, access logs in logs-spool.json) on disk until the
// console acknowledged them. The sequence and the immutable payload of a
// batch are written before it is sent: a lost acknowledgement, a failed
// write of one or an agent restart resends the same sequence. Reading the
// console's cursor also recovers safely after a lost or corrupt file:
// fresh batches never reuse an accepted sequence.

// maxSpoolSequence is the last sequence a spool hands out.
const maxSpoolSequence = math.MaxInt64

// spoolBatch is one report call of a spool.
type spoolBatch[B any] interface {
	sequence() uint64
	// numbered returns the batch with sequence seq.
	numbered(seq uint64) B
	// size is the number of buckets or records in the batch.
	size() int
	// firstMinute is the earliest minute in the batch (zero for none or
	// when the report has no watermark); dropping the batch holds the
	// watermark there.
	firstMinute() time.Time
}

// spoolFile is the content of a spool file.
type spoolFile[B spoolBatch[B]] struct {
	NodeID  string `json:"node_id"`
	Last    uint64 `json:"last"`
	Batches []B    `json:"batches"`
	// Loose holds batches drained before the console's cursor was read
	// (no sequence yet); they are numbered after it.
	Loose []B `json:"loose,omitempty"`
	// LostFrom is the first minute of buckets dropped for the spool limits
	// (Unix seconds, 0 for none): the watermark stays there for
	// statsLossHold.
	LostFrom int64 `json:"lost_from,omitempty"`
}

func (f *spoolFile[B]) pending() int {
	n := 0
	for _, b := range f.Batches {
		n += b.size()
	}
	for _, b := range f.Loose {
		n += b.size()
	}
	return n
}

// dropOldest drops the oldest unsent batch (numbered ones first, they are
// older) and records the first minute it held. It returns the buckets
// dropped; false when there was nothing to drop.
func (f *spoolFile[B]) dropOldest() (int, bool) {
	var b B
	switch {
	case len(f.Batches) > 0:
		b, f.Batches = f.Batches[0], f.Batches[1:]
	case len(f.Loose) > 0:
		b, f.Loose = f.Loose[0], f.Loose[1:]
	default:
		return 0, false
	}
	if first := b.firstMinute(); !first.IsZero() && (f.LostFrom == 0 || first.Unix() < f.LostFrom) {
		f.LostFrom = first.Unix()
	}
	return b.size(), true
}

// spool is a spool file with its limits: at most maxBytes on disk, at most
// maxPending buckets or records in all, at most batchSize in a batch. what
// names the content in log messages, rpc the call that reports it.
type spool[B spoolBatch[B]] struct {
	a          *Agent
	path       string
	what, rpc  string
	maxBytes   int64
	maxPending int
	batchSize  int
}

// load reads the spool of node nodeID; a missing, oversized or unreadable
// one, or one of another identity, starts over. The error is one of
// reading the file.
func (s *spool[B]) load(nodeID string) (*spoolFile[B], error) {
	f := &spoolFile[B]{NodeID: nodeID}
	info, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Size() > s.maxBytes {
		s.a.log.Warn("discarding an oversized " + s.what + " spool")
		return f, nil
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, f); err != nil || f.NodeID != nodeID {
		s.a.log.Warn("discarding unreadable or previous-identity " + s.what + " spool")
		return &spoolFile[B]{NodeID: nodeID}, nil
	}
	return f, nil
}

// sync drops the batches the console acknowledged (cursor is its last
// sequence), numbers the loose ones after the rest and saves the spool.
func (s *spool[B]) sync(f *spoolFile[B], cursor uint64) error {
	last := max(f.Last, cursor)
	var remaining []B
	previous := cursor
	for _, b := range f.Batches {
		if b.sequence() <= cursor {
			continue
		}
		if b.sequence() <= previous || b.sequence() > last || b.size() > s.batchSize {
			return fmt.Errorf("invalid %s spool ordering", s.what)
		}
		remaining = append(remaining, b)
		previous = b.sequence()
	}
	for _, b := range f.Loose {
		if last >= maxSpoolSequence {
			return fmt.Errorf("%s sequence exhausted", s.what)
		}
		last++
		remaining = append(remaining, b.numbered(last))
	}
	f.Last, f.Batches, f.Loose = last, remaining, nil
	return s.save(f)
}

// add adds the batches pack makes: numbered after f.Last once the
// console's cursor is known (synced), loose before. Beyond maxPending the
// oldest batches are dropped. It returns false when the sequence is
// exhausted.
func (s *spool[B]) add(f *spoolFile[B], synced bool, pack func(last uint64) ([]B, bool)) bool {
	if synced {
		batches, ok := pack(f.Last)
		if !ok {
			s.a.log.Error(s.what + " sequence exhausted")
			return false
		}
		if len(batches) > 0 {
			f.Batches = append(f.Batches, batches...)
			f.Last = batches[len(batches)-1].sequence()
		}
	} else if batches, _ := pack(0); len(batches) > 0 {
		for _, b := range batches {
			f.Loose = append(f.Loose, b.numbered(0))
		}
	}
	for f.pending() > s.maxPending {
		n, _ := f.dropOldest()
		s.a.log.Warn("dropping oldest unsent "+s.what+" batch: bucket limit", s.dropped(f, n)...)
	}
	return true
}

// save writes the spool, dropping the oldest batches while it is larger
// than maxBytes.
func (s *spool[B]) save(f *spoolFile[B]) error {
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	for int64(len(raw)) > s.maxBytes {
		n, ok := f.dropOldest()
		if !ok {
			break
		}
		s.a.log.Warn("dropping oldest unsent "+s.what+" batch: spool size limit", s.dropped(f, n)...)
		if raw, err = json.Marshal(f); err != nil {
			return err
		}
	}
	return fsutil.WriteFileAtomic(s.path, raw, 0600)
}

func (s *spool[B]) dropped(f *spoolFile[B], n int) []any {
	if f.LostFrom == 0 {
		return []any{"buckets", n}
	}
	return []any{"buckets", n, "lost_from", time.Unix(f.LostFrom, 0).UTC()}
}

// upload sends the numbered batches in order with send, which returns the
// sequence the console acknowledged. Each acknowledgement is saved before
// the next batch goes; the first failure ends the round (the batch is
// sent again next time). It returns the spool as saved.
func (s *spool[B]) upload(ctx context.Context, f *spoolFile[B], send func(context.Context, B) (uint64, error)) *spoolFile[B] {
	for len(f.Batches) > 0 {
		b := f.Batches[0]
		acked, err := send(ctx, b)
		if err != nil {
			if ctx.Err() == nil {
				s.a.logRPCError(s.rpc+" failed; will retry the same batch", err)
			}
			break
		}
		if acked != b.sequence() {
			s.a.log.Warn(s.what + " acknowledgement sequence mismatch")
			break
		}
		next := *f
		next.Batches = f.Batches[1:]
		if err := s.save(&next); err != nil {
			s.a.log.Error("cannot persist "+s.what+" acknowledgement; batch will be retried", "err", err)
			break
		}
		f = &next
		s.a.markConnected()
	}
	return f
}
