package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// IsID reports whether s is a message's id as this box names it: the
// SHA-256 of its ciphertext, as 64 lowercase hex. Each file inbox/, held/ and
// quarantine/ keep is named by one.
func IsID(s string) bool { return hexID.MatchString(s) }

// InboxLine returns the line inbox/<id>.json keeps: the message's checked
// fields, as recv printed them. An id that is not one is refused before any
// file is read.
func (b *Box) InboxLine(id string) ([]byte, error) {
	if !IsID(id) {
		return nil, errors.New("not a message's id: 64 lowercase hex, as recv prints it")
	}
	l, err := os.ReadFile(b.path("inbox", id+".json")) //nolint:gosec // a path inside the box's own directory, named by 64 hex
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("inbox/ holds no message %s", id)
	}
	return l, err
}

// keptRefusal is a refused message as quarantine/<id>.json keeps it: the
// message as served, whole, for whoever looks into who sent what: the
// members of its list entry, and the ciphertext its fetch answered, in
// base64. Each of the server's strings is in the clear only when it has its
// form (an id or an address is 64 lowercase hex, a time is one
// protocol.ParseTime reads), and is otherwise kept as <name>_b64, the string
// as served in base64. So nothing the server chose is readable at a glance,
// and nothing is lost. Its size is the ciphertext's, which the fetch was
// held to. irongall.sh's ig_kept keeps the same.
type keptRefusal struct {
	ID            string         `json:"id,omitempty"`
	IDB64         string         `json:"id_b64,omitempty"`
	From          string         `json:"from,omitempty"`
	FromB64       string         `json:"from_b64,omitempty"`
	ReceivedAt    string         `json:"received_at,omitempty"`
	ReceivedAtB64 string         `json:"received_at_b64,omitempty"`
	ExpiresAt     string         `json:"expires_at,omitempty"`
	ExpiresAtB64  string         `json:"expires_at_b64,omitempty"`
	Ciphertext    protocol.Bytes `json:"ciphertext"`
}

func keepRefused(m *protocol.MessageInfo, ct []byte) ([]byte, error) {
	k := keptRefusal{Ciphertext: ct}
	for _, f := range []struct {
		served       string
		plain, coded *string
		ok           bool
	}{
		{m.ID, &k.ID, &k.IDB64, IsID(m.ID)},
		{m.From, &k.From, &k.FromB64, IsID(m.From)},
		{m.ReceivedAt, &k.ReceivedAt, &k.ReceivedAtB64, isTime(m.ReceivedAt)},
		{m.ExpiresAt, &k.ExpiresAt, &k.ExpiresAtB64, isTime(m.ExpiresAt)},
	} {
		switch {
		case f.served == "":
		case f.ok:
			*f.plain = f.served
		default:
			*f.coded = base64.StdEncoding.EncodeToString([]byte(f.served))
		}
	}
	return json.Marshal(k)
}

func isTime(s string) bool { _, err := protocol.ParseTime(s); return err == nil }

// Quarantined is a refused message in quarantine/, in this client's words:
// its id, the code it was refused for, and the sender and the time the
// server gave, each only when it has its form. Nothing else of what the
// server or the sender wrote is in it.
type Quarantined struct {
	ID         string `json:"id"`
	Code       string `json:"code"`
	From       string `json:"from,omitempty"`
	ReceivedAt string `json:"received_at,omitempty"`
}

// Quarantined lists quarantine/, by id. A file is read whichever form it was
// kept in, and each value is held to its form again as it is read.
func (b *Box) Quarantined() ([]Quarantined, error) {
	names, err := filepath.Glob(b.path("quarantine", "*.json"))
	if err != nil {
		return nil, err
	}
	var qs []Quarantined
	for _, name := range names {
		id := strings.TrimSuffix(filepath.Base(name), ".json")
		if !IsID(id) {
			continue
		}
		q := Quarantined{ID: id, Code: b.quarantineCode(id)}
		var kept struct {
			From       any `json:"from"`
			ReceivedAt any `json:"received_at"`
		}
		if data, err := os.ReadFile(name); err == nil && json.Unmarshal(data, &kept) == nil { //nolint:gosec // a path inside the box's own directory
			if s, ok := kept.From.(string); ok && IsID(s) {
				q.From = s
			}
			if s, ok := kept.ReceivedAt.(string); ok && isTime(s) {
				q.ReceivedAt = s
			}
		}
		qs = append(qs, q)
	}
	return qs, nil
}

// quarantineCode is the code a refused message's .reason file starts with,
// which this client wrote; "unknown" when it does not start with one.
func (b *Box) quarantineCode(id string) string {
	data, err := os.ReadFile(b.path("quarantine", id+".reason")) //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return "unknown"
	}
	if c, _, ok := strings.Cut(string(data), ":"); ok && codeGrammar.MatchString(c) {
		return c
	}
	return "unknown"
}

// RemoveQuarantined deletes refused messages from quarantine/, each with its
// .reason, and returns the ids it deleted; with no ids it deletes them all.
// An id that is not one, or that quarantine/ does not hold, is refused
// before anything is deleted.
//
// It holds the box's lock from start to end ([Box.hold]), as every command
// that writes the box does.
func (b *Box) RemoveQuarantined(ctx context.Context, ids []string) ([]string, error) {
	return locked(ctx, b, func() ([]string, error) {
		if len(ids) == 0 {
			qs, err := b.Quarantined()
			if err != nil {
				return nil, err
			}
			for _, q := range qs {
				ids = append(ids, q.ID)
			}
		}
		for _, id := range ids {
			if !IsID(id) {
				return nil, errors.New("not a message's id: 64 lowercase hex, as irongall quarantine list prints it")
			}
			if _, err := os.Stat(b.path("quarantine", id+".json")); err != nil {
				return nil, fmt.Errorf("quarantine/ holds no message %s: nothing is deleted", id)
			}
		}
		var gone []string
		for _, id := range slices.Compact(slices.Sorted(slices.Values(ids))) {
			if err := os.Remove(b.path("quarantine", id+".json")); err != nil {
				return gone, err
			}
			if err := os.Remove(b.path("quarantine", id+".reason")); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return gone, err
			}
			gone = append(gone, id)
		}
		return gone, nil
	})
}
