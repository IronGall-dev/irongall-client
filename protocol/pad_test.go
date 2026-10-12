package protocol

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// sealedLen is the size age itself gives n bytes encrypted to r.
func sealedLen(t *testing.T, r age.Recipient, plaintext []byte) int {
	t.Helper()
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return ct.Len()
}

func recipients(t *testing.T) map[KeyType]age.Recipient {
	t.Helper()
	classic, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pq, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return map[KeyType]age.Recipient{Classic: classic.Recipient(), PostQuantum: pq.Recipient()}
}

// SealedSize is age's own arithmetic, held here against age: for each key
// type, on each side of a chunk's end, and for a file of many chunks.
func TestSealedSizeIsWhatAgeWrites(t *testing.T) {
	for kt, r := range recipients(t) {
		for _, n := range []int{0, 1, 100, ageChunk - 1, ageChunk, ageChunk + 1, 2*ageChunk - 1, 2 * ageChunk, 2*ageChunk + 1, 5*ageChunk + 12345} {
			if got, want := SealedSize(kt, n), sealedLen(t, r, make([]byte, n)); got != want {
				t.Errorf("%s, %d bytes: SealedSize says %d, age wrote %d", kt, n, got, want)
			}
		}
		// The header's size never varies from one file to the next.
		for range 50 {
			if got := sealedLen(t, r, []byte("x")); got != SealedSize(kt, 1) {
				t.Fatalf("%s: a second file of the same plaintext is %d bytes, not %d", kt, got, SealedSize(kt, 1))
			}
		}
	}
}

// The block is 1/16 of the size, as a power of two, and never under 1 KiB.
func TestPaddedSize(t *testing.T) {
	const k = 1024
	for _, c := range []struct{ size, block, padded int }{
		{1, k, k},
		{k, k, k},
		{k + 1, k, 2 * k},
		{16 * k, k, 16 * k},
		{16*k + 1, 2 * k, 18 * k}, // just past 16 KiB: 2 KiB blocks
		{16*k + 100, 2 * k, 18 * k},
		{32 * k, 2 * k, 32 * k},
		{32*k + 1, 4 * k, 36 * k},
		{64 * k, 4 * k, 64 * k},
		{64*k + 1, 8 * k, 72 * k},
		{100 * k, 8 * k, 104 * k},
		{10 << 20, 1 << 20, 10 << 20},
		{10<<20 + 1, 1 << 20, 11 << 20},
	} {
		if got := PadBlock(c.size); got != c.block {
			t.Errorf("PadBlock(%d) = %d, want %d", c.size, got, c.block)
		}
		if got := PaddedSize(c.size); got != c.padded {
			t.Errorf("PaddedSize(%d) = %d, want %d", c.size, got, c.padded)
		}
	}
	// A padded size is padded to itself, is never under the size, and adds
	// less than one block: so at most 1/8 past 16 KiB.
	for size := 1; size < 300*k; size += 7 {
		p := PaddedSize(size)
		if p < size || p-size >= PadBlock(size) || PaddedSize(p) != p || p%PadBlock(p) != 0 {
			t.Fatalf("PaddedSize(%d) = %d", size, p)
		}
		if size > 16*k && (p-size)*8 > size {
			t.Fatalf("PaddedSize(%d) = %d adds more than 1/8", size, p)
		}
	}
}

// Every size a ciphertext can be padded to is the size of some age file, for
// both key types, up to 1 GiB: the 16 sizes no file has, after each full
// chunk, do not fall on a block there. The first that does is 3 GiB, for an
// X25519 key, and padding steps past it to the next block.
func TestEveryPaddedSizeIsAnAgeFile(t *testing.T) {
	for _, kt := range []KeyType{Classic, PostQuantum} {
		for size := PaddedSize(SealedSize(kt, 0)); size <= 1<<30; size = PaddedSize(size + 1) {
			n, ok := plaintextSize(kt, size)
			if !ok || SealedSize(kt, n) != size {
				t.Fatalf("%s: no plaintext seals to %d bytes", kt, size)
			}
		}
		if _, ok := plaintextSize(kt, ageHeader(kt)+ageNonce+ageTag-1); ok {
			t.Errorf("%s: a file smaller than an empty one has a plaintext", kt)
		}
		if _, ok := plaintextSize(kt, SealedSize(kt, ageChunk)+1); ok {
			t.Errorf("%s: a file one byte past a full chunk has a plaintext", kt)
		}
	}
	if strconv.IntSize < 64 {
		t.Skip("the 3 GiB case needs a 64-bit int")
	}
	gib := 1 << 30
	if _, ok := plaintextSize(Classic, 3*gib); ok {
		t.Fatal("an X25519 file of exactly 3 GiB has a plaintext: the case below tests nothing")
	}
	// An envelope whose file would be padded to 3 GiB goes to the block after.
	bare, _ := plaintextSize(Classic, 3*gib-5000)
	sealed, filler := padTo(Classic, bare)
	if want := 3*gib + PadBlock(3*gib); sealed != want || SealedSize(Classic, bare+padMember+filler) != sealed {
		t.Fatalf("padTo at 3 GiB: %d bytes with %d of filler, want %d", sealed, filler, want)
	}
}

// A size limit that is a whole number of its own blocks is not passed by
// padding: a message fits it padded if it fits it with the 9 bytes of an
// empty pad member. So the client never needs to know the limit, and what
// padding costs at a limit is those 9 bytes and no more.
func TestPaddingAtALimit(t *testing.T) {
	for _, limit := range []int{64 << 10, 10 << 20} {
		if PaddedSize(limit) != limit {
			t.Fatalf("%d is not a whole number of its own blocks", limit)
		}
		for _, kt := range []KeyType{Classic, PostQuantum} {
			top, ok := plaintextSize(kt, limit) // the largest envelope whose file is within the limit
			if !ok {
				t.Fatalf("%s: no envelope's file is exactly %d bytes", kt, limit)
			}
			over := 0
			for bare := top - 40; bare <= top; bare++ {
				sealed, _ := padTo(kt, bare)
				want := SealedSize(kt, bare+padMember) <= limit
				if (sealed <= limit) != want {
					t.Errorf("%s, limit %d: an envelope whose file is %d bytes is padded to %d", kt, limit, SealedSize(kt, bare), sealed)
				}
				if sealed > limit {
					over++
				}
			}
			if over != padMember {
				t.Errorf("%s, limit %d: the largest envelope is %d bytes smaller than without padding, want %d", kt, limit, over, padMember)
			}
		}
	}
}

func padEnvelope(t *testing.T, body string) *Envelope {
	t.Helper()
	a := Address{1}
	e, err := NewEnvelope(a, a, body, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// A padded envelope's age file is a whole number of blocks, by age's own
// count, for bodies on each side of every boundary; the padding is the least
// that does it; and the envelope reads back as the one that was padded.
func TestMarshalPaddedLandsOnABlock(t *testing.T) {
	rs := recipients(t)
	bare, err := padEnvelope(t, "").Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, kt := range []KeyType{Classic, PostQuantum} {
		// Body lengths that put the unpadded file within a few bytes of a
		// boundary, on each side, at 1, 2, 16, 18, 32, 36, 64 and 72 KiB,
		// and past a chunk's end.
		var bodies []int
		for _, edge := range []int{1 << 10, 2 << 10, 16 << 10, 18 << 10, 32 << 10, 36 << 10, 64 << 10, 72 << 10, 136 << 10} {
			at := edge - SealedSize(kt, len(bare)) // the body whose bare file is edge bytes, were it one chunk
			for d := -12; d <= 3; d++ {
				if at+d >= 0 {
					bodies = append(bodies, at+d)
				}
			}
		}
		bodies = append(bodies, 0, 1, 2, 3, 6, 7, 100, 900, ageChunk-300, ageChunk, ageChunk+300)
		for _, n := range bodies {
			e := padEnvelope(t, strings.Repeat("a", n))
			e.Pad = "what was here is replaced"
			p, sealed, err := e.MarshalPadded(kt)
			if err != nil {
				t.Fatalf("%s, a body of %d: %v", kt, n, err)
			}
			if got := sealedLen(t, rs[kt], p); got != sealed {
				t.Fatalf("%s, a body of %d: age wrote %d bytes, MarshalPadded said %d", kt, n, got, sealed)
			}
			if sealed != PaddedSize(sealed) {
				t.Fatalf("%s, a body of %d: %d bytes is not a whole number of %d-byte blocks", kt, n, sealed, PadBlock(sealed))
			}
			// The least padding: the first block with room for the member,
			// which every envelope carries.
			withMember := SealedSize(kt, len(bare)+n+padMember)
			if want := PaddedSize(withMember); sealed != want {
				t.Fatalf("%s, a body of %d (%d bytes with an empty pad): padded to %d, want %d", kt, n, withMember, sealed, want)
			}
			if !bytes.Contains(p, []byte(`,"pad":"`)) || (sealed == withMember) != bytes.HasSuffix(p, []byte(`,"pad":""}`)) {
				t.Fatalf("%s, a body of %d: %d → %d bytes, and the pad member is wrong: …%s", kt, n, withMember, sealed, p[max(0, len(p)-40):])
			}
			got, err := OpenEnvelope(p, e.From, e.To, e.SentAt)
			if err != nil {
				t.Fatalf("%s, a body of %d: the padded envelope does not open: %v", kt, n, err)
			}
			if got.MsgID != e.MsgID || !bytes.Equal(got.Body, e.Body) || strings.Trim(got.Pad, padFiller) != "" {
				t.Fatalf("%s, a body of %d: the padded envelope is not the same message", kt, n)
			}
		}
	}
}

// What the padding is for: bodies of different lengths are one size on the
// wire. And where the first boundaries fall, which the README states.
func TestShortBodiesAreOneSize(t *testing.T) {
	sizeOf := func(kt KeyType, body string) int {
		_, sealed, err := padEnvelope(t, body).MarshalPadded(kt)
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}
	for _, c := range []struct {
		kt     KeyType
		bodies []string
		size   int
	}{
		{PostQuantum, []string{"", "no", "yes", "reject", "approve", strings.Repeat("a", 136)}, 2048},
		{PostQuantum, []string{strings.Repeat("a", 137), strings.Repeat("a", 1160)}, 3072},
		{Classic, []string{"", "no", "yes", strings.Repeat("a", 571)}, 1024},
		{Classic, []string{strings.Repeat("a", 572), strings.Repeat("a", 1595)}, 2048},
	} {
		for _, b := range c.bodies {
			if got := sizeOf(c.kt, b); got != c.size {
				t.Errorf("%s, a body of %d bytes: %d on the wire, want %d", c.kt, len(b), got, c.size)
			}
		}
	}
}
