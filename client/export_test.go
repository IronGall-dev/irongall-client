package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
	bolt "go.etcd.io/bbolt"
)

// Code is the error's code, if err is an [APIError], for a test that knows
// which call answered.
func Code(err error) protocol.Code { return code(err) }

// PassRefused reports whether c refuses the pass a call carried, so that the
// mailbox signs another and tries once more (passRefused).
func PassRefused(c protocol.Code) bool { return passRefused(c) }

// ProvedCodes are the answers about a revocation that proved checks and
// never believes (provedCodes).
func ProvedCodes() []protocol.Code { return slices.Clone(provedCodes) }

// Undeliverable are the answers that end a message for good (undeliverable).
func Undeliverable() []protocol.Code { return slices.Clone(undeliverable) }

// RemovePrekey deletes prekey n as a prune does (removePrekey), under the
// mailbox's lock, for a test.
func (b *Mailbox) RemovePrekey(ctx context.Context, n uint64) error {
	_, err := locked(ctx, b, func() (struct{}, error) { return struct{}{}, b.removePrekey(n) })
	return err
}

// SetLockPatience shortens how long a command waits for the mailbox's lock, for
// one test.
func SetLockPatience(t *testing.T, d time.Duration) {
	old := lockPatience
	lockPatience = d
	t.Cleanup(func() { lockPatience = old })
}

// SetFormatSteps makes this client's format one above the steps given, each
// bringing a mailbox forward one format (formatSteps), for one test.
func SetFormatSteps(t *testing.T, steps ...func(*Mailbox) error) {
	old := formatSteps
	formatSteps = steps
	t.Cleanup(func() { formatSteps = old })
}

// ClientFormat is the format this client reads and writes (clientFormat).
func ClientFormat() int { return clientFormat() }

// SetFormat records raw as the format of the mailbox in dir, or with raw nil
// none, as another client would have left it.
func SetFormat(t *testing.T, dir string, raw []byte) {
	t.Helper()
	db, err := bolt.Open(filepath.Join(dir, "state"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // written in its transaction
	if err := db.Update(func(tx *bolt.Tx) error {
		if raw == nil {
			if bk := tx.Bucket([]byte(bucketMeta)); bk != nil {
				return bk.Delete([]byte(keyFormat))
			}
			return nil
		}
		bk, err := tx.CreateBucketIfNotExists([]byte(bucketMeta))
		if err != nil {
			return err
		}
		return bk.Put([]byte(keyFormat), raw)
	}); err != nil {
		t.Fatal(err)
	}
}

// HasGate reports whether this system has the mailbox's gate (tryGate): where
// it has none (gate_other.go), a waiting writer has no preference over
// readings.
func HasGate(t *testing.T) bool {
	f, _, err := tryGate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if f == nil {
		return false
	}
	_ = f.Close()
	return true
}

// SetRequestTimeout shortens how long the default HTTP client lets a request
// go, for one test: one that sends or fetches a ciphertext with no byte of it
// moving, and any other whole.
func SetRequestTimeout(t *testing.T, d time.Duration) {
	old := requestTimeout
	requestTimeout = d
	t.Cleanup(func() { requestTimeout = old })
}

// Bounded has a mailbox whose client it was given bound its calls as the
// default client does (stall): a test whose server is in memory, reached
// only by that server's client, tests the default client's bounds.
func Bounded(b *Mailbox) *Mailbox {
	b.stall = true
	return b
}

// KeepAliveOf is the keep-alive a new connection of b's default client
// gets now: none is zero.
func KeepAliveOf(b *Mailbox) time.Duration {
	_, ka := b.holding.current()
	return ka
}

// Partial is what the mailbox's state records of its partial file: which
// message it is of, and how many of its bytes are synced; "" and 0 for none.
func (b *Mailbox) Partial() (string, int64, error) { return b.partialRecord() }

// SetDrainLimits lowers what one drain takes, for one test.
func SetDrainLimits(t *testing.T, messages, bytes, pages int) {
	m, b, p := maxDrainMessages, maxDrainBytes, maxDrainPages
	maxDrainMessages, maxDrainBytes, maxDrainPages = messages, bytes, pages
	t.Cleanup(func() { maxDrainMessages, maxDrainBytes, maxDrainPages = m, b, p })
}

// SetStep has f called with the name of each step a command passes
// (steps.go), for a test that kills its process at one.
func SetStep(f func(name string)) { atStep = f }

// SetWriteFault has each write of the mailbox's state ask f first, and fail
// with the error it gives, for one test: a fault of the mailbox itself, at the
// writes a test chooses (SetStep tells it where a command is).
func SetWriteFault(t *testing.T, f func() error) {
	failWrite = f
	t.Cleanup(func() { failWrite = nil })
}

// Steps are the steps of one kind of write (steps.go).
func Steps(kind string) []string { return steps[kind] }

// PutRevocations puts a record to the server as it is, with none of the
// checks Revoke makes first: what a client that skipped them would send.
func PutRevocations(ctx context.Context, opt Options, a protocol.Address, rec *protocol.Revocations) (*http.Response, error) {
	b, err := newMailbox("", opt)
	if err != nil {
		return nil, err
	}
	return b.call(ctx, http.MethodPut, "/v1/"+a.String()+"/revocations", rec, nil, nil)
}

// Records is what the mailbox's state keeps, each record by the name of the file
// that held it before the state file did: "serial", "pass", "etag",
// "seen-floor", "acl.json", "revoked.sig", "revoked-certs.json", "seen" (the
// replay set's lines, "<hash> <sent_at> <from> <msg_id>", by sent_at),
// "peers/<address>/<part>" (identity.doc, serial, rank, prekey.txt,
// prekey.sig, revoke.sig, revoked-certs.json), "prekeys/<serial>.<part>"
// (txt, txt.sig, made) and "refused/<id>.reason" ("<code>: <reason>"),
// each a record's bytes as that file held them; and the records no file held,
// "renewal" (the number of the renewal under way), "acl-read" (the read of
// the server's ACL a renewal recv began owes), "adopt-acl" (a restore's
// adoption of its server's ACL, begun), "renew-failed", "not-made",
// "acl-another-writer", "acl-replaced", "partial" (the message the
// partial file is of, and how many of its bytes are synced) and "format"
// (the mailbox's format, as it is recorded). So a test
// reads and changes the mailbox's state as it did its files.
func (b *Mailbox) Records() (map[string][]byte, error) {
	out := map[string][]byte{}
	err := b.view(func(s store) error {
		for _, r := range []struct{ key, name string }{
			{"serial", "serial"}, {"pass", "pass"}, {"etag", "etag"}, {"seen-floor", "seen-floor"},
			{"acl", "acl.json"}, {"revoked", "revoked.sig"}, {"revoked-certs", "revoked-certs.json"},
			{"renew-failed", "renew-failed"}, {"not-made", "not-made"}, {"acl-another-writer", "acl-another-writer"}, {"acl-replaced", "acl-replaced"}, {"partial", "partial"},
			{"deprecation", "deprecation"}, {"sunset", "sunset"}, {"document-read", "document-read"}, {"latest", "latest"},
		} {
			if v := s.get(bucketMailbox, r.key); v != nil {
				out[r.name] = v
			}
		}
		if err := s.each(bucketPeers, func(k, v []byte) error {
			var p peerRecord
			if err := protocol.Unmarshal(v, &p); err != nil {
				return err
			}
			d := "peers/" + string(k) + "/"
			out[d+"identity.doc"] = p.Identity
			for _, part := range []struct {
				name string
				v    []byte
			}{{"prekey.txt", p.Prekey}, {"prekey.sig", p.PrekeySignature}, {"revoke.sig", p.Revocation}} {
				if part.v != nil {
					out[d+part.name] = part.v
				}
			}
			if p.Serial != 0 {
				out[d+"serial"] = strconv.AppendUint(nil, p.Serial, 10)
				out[d+"rank"] = strconv.AppendUint(nil, p.Rank, 10)
			}
			if p.RevokedCertificates != nil {
				line, err := json.Marshal(protocol.Revocations{Identity: p.Identity, RevokedCertificates: p.RevokedCertificates, RevokedCertificatesSignature: p.RevokedCertificatesSignature})
				if err != nil {
					return err
				}
				out[d+"revoked-certs.json"] = line
			}
			return nil
		}); err != nil {
			return err
		}
		var seen []byte
		if err := s.each(bucketSeenTime, func(k, _ []byte) error {
			h := string(k[8:])
			seen = fmt.Appendf(seen, "%s %s\n", h, s.get(bucketSeen, h))
			return nil
		}); err != nil {
			return err
		}
		if seen != nil {
			out["seen"] = seen
		}
		if err := s.each(bucketPrekeys, func(k, v []byte) error {
			n, err := keySerial(k)
			if err != nil {
				return err
			}
			var p prekeyRecord
			if err := protocol.Unmarshal(v, &p); err != nil {
				return err
			}
			stem := "prekeys/" + strconv.FormatUint(n, 10)
			out[stem+".txt"], out[stem+".txt.sig"], out[stem+".made"] = p.Statement, p.Signature, []byte(p.Made)
			return nil
		}); err != nil {
			return err
		}
		if v := s.get(bucketMeta, keyFormat); v != nil {
			out["format"] = v
		}
		for _, k := range []string{"renewal", "acl-read", "adopt-acl"} {
			if v := s.get(bucketIntent, k); v != nil {
				out[k] = v
			}
		}
		return s.each(bucketRefused, func(k, v []byte) error {
			var q refusedRecord
			if err := protocol.Unmarshal(v, &q); err != nil {
				return err
			}
			out["refused/"+string(k)+".reason"] = []byte(q.Code + ": " + q.Reason)
			return nil
		})
	})
	return out, err
}

// Record is one of what [Mailbox.Records] gives, and whether the mailbox keeps it.
func (b *Mailbox) Record(t *testing.T, name string) ([]byte, bool) {
	t.Helper()
	all, err := b.Records()
	if err != nil {
		t.Fatal(err)
	}
	v, ok := all[name]
	return v, ok
}

// SetRecord writes a record by its name in [Mailbox.Records], or with v nil
// deletes it, as a test that wrote or removed the file did: as another
// machine of the mailbox, a fault or an earlier state would leave it. It
// holds the mailbox's lock to.
func (b *Mailbox) SetRecord(t *testing.T, name string, v []byte) {
	t.Helper()
	err := b.lockedFinishedDo(context.Background(), func() error {
		return b.update(func(s store) error {
			put := func(bucket, key string, v []byte) error {
				if v == nil {
					return s.del(bucket, key)
				}
				return s.put(bucket, key, v)
			}
			for key, file := range map[string]string{"serial": "serial", "pass": "pass", "etag": "etag", "seen-floor": "seen-floor", "acl": "acl.json", "revoked": "revoked.sig", "revoked-certs": "revoked-certs.json", "renew-failed": "renew-failed", "not-made": "not-made", "acl-another-writer": "acl-another-writer", "acl-replaced": "acl-replaced"} {
				if name == file {
					return put(bucketMailbox, key, v)
				}
			}
			if rest, ok := strings.CutPrefix(name, "peers/"); ok {
				addr, part, _ := strings.Cut(rest, "/")
				a, err := protocol.ParseAddress(addr)
				if err != nil {
					return err
				}
				p, err := b.peerOf(s, a)
				if err != nil {
					return err
				}
				if p == nil {
					p = &peerRecord{}
				}
				switch part {
				case "identity.doc":
					p.Identity = v
				case "revoke.sig":
					p.Revocation = v
				case "revoked-certs.json":
					var rec protocol.Revocations
					if v != nil {
						if err := protocol.Unmarshal(v, &rec); err != nil {
							return err
						}
					}
					p.RevokedCertificates, p.RevokedCertificatesSignature = rec.RevokedCertificates, rec.RevokedCertificatesSignature
				default:
					return fmt.Errorf("no record %s", name)
				}
				if p.Identity == nil {
					return s.del(bucketPeers, a.String())
				}
				raw, err := json.Marshal(p)
				if err != nil {
					return err
				}
				return s.put(bucketPeers, a.String(), raw)
			}
			if name == "seen" && v == nil {
				for _, bk := range []string{bucketSeen, bucketSeenSender, bucketSeenTime} {
					if err := s.tx.DeleteBucket([]byte(bk)); err != nil && s.tx.Bucket([]byte(bk)) != nil {
						return err
					}
				}
				return nil
			}
			if rest, ok := strings.CutPrefix(name, "prekeys/"); ok {
				stem, part, _ := strings.Cut(rest, ".")
				n, err := strconv.ParseUint(stem, 10, 64)
				if err != nil {
					return err
				}
				var p prekeyRecord
				if raw := s.get(bucketPrekeys, serialKey(n)); raw != nil {
					if err := protocol.Unmarshal(raw, &p); err != nil {
						return err
					}
				}
				switch part {
				case "txt":
					p.Statement = v
				case "txt.sig":
					p.Signature = v
				case "made":
					p.Made = string(v)
				default:
					return fmt.Errorf("no record %s", name)
				}
				if len(p.Statement) == 0 && len(p.Signature) == 0 {
					return s.del(bucketPrekeys, serialKey(n))
				}
				raw, err := json.Marshal(p)
				if err != nil {
					return err
				}
				return s.put(bucketPrekeys, serialKey(n), raw)
			}
			if name == "renewal" || name == "acl-read" || name == "adopt-acl" {
				return put(bucketIntent, name, v)
			}
			if rest, ok := strings.CutPrefix(name, "refused/"); ok {
				id, isReason := strings.CutSuffix(rest, ".reason")
				if !isReason {
					return fmt.Errorf("no record %s", name)
				}
				if v == nil {
					return s.del(bucketRefused, id)
				}
				code, reason, _ := strings.Cut(string(v), ": ")
				raw, err := json.Marshal(refusedRecord{Code: code, Reason: reason})
				if err != nil {
					return err
				}
				return s.put(bucketRefused, id, raw)
			}
			return fmt.Errorf("no record %s", name)
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

// RecordsAt is [Mailbox.Records] of the mailbox in dir, read without opening the mailbox,
// which would make what a mailbox has: for a test that looks at a directory as a
// command left it.
func RecordsAt(dir string) (map[string][]byte, error) { return (&Mailbox{dir: dir}).Records() }
