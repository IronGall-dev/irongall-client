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
	// A message whose file would be padded to 3 GiB goes to the block after.
	bare, _ := plaintextSize(Classic, 3*gib-5000)
	sealed, filler := padTo(Classic, bare)
	if want := 3*gib + PadBlock(3*gib); sealed != want || SealedSize(Classic, bare+filler) != sealed {
		t.Fatalf("padTo at 3 GiB: %d bytes with %d of filler, want %d", sealed, filler, want)
	}
}

// A size limit that is a whole number of its own blocks is not passed by
// padding: a message fits it padded exactly when it fits it bare. So the
// client never needs to know the limit, and padding costs nothing at one.
// The protocol's largest ciphertext is such a limit (PROTOCOL.md §11.10).
func TestPaddingAtALimit(t *testing.T) {
	for _, limit := range []int{64 << 10, 10 << 20, MaxCiphertext} {
		if PaddedSize(limit) != limit {
			t.Fatalf("%d is not a whole number of its own blocks", limit)
		}
		for _, kt := range []KeyType{Classic, PostQuantum} {
			top, ok := plaintextSize(kt, limit) // the largest message whose file is within the limit
			if !ok {
				t.Fatalf("%s: no message's file is exactly %d bytes", kt, limit)
			}
			for bare := top - 40; bare <= top+40; bare++ {
				sealed, filler := padTo(kt, bare)
				if (sealed <= limit) != (bare <= top) {
					t.Errorf("%s, limit %d: a message whose file is %d bytes is padded to %d", kt, limit, SealedSize(kt, bare), sealed)
				}
				if bare == top && filler != 0 {
					t.Errorf("%s, limit %d: a message already on the limit gets %d bytes of padding", kt, limit, filler)
				}
			}
		}
	}
}

// What is encrypted is the line, the signature and the padding, in that
// order; its age file is a whole number of blocks, by age's own count, for
// messages on each side of every boundary; and the padding is the least that
// does it.
func TestPlaintextLandsOnABlock(t *testing.T) {
	rs := recipients(t)
	sig := bytes.Repeat([]byte{'s'}, 846)
	for _, kt := range []KeyType{Classic, PostQuantum} {
		// Message lengths that put the unpadded file within a few bytes of a
		// boundary, on each side, at 2, 4, 16, 18, 32, 36, 64 and 72 KiB,
		// and past a chunk's end.
		var sizes []int
		for _, edge := range []int{2 << 10, 4 << 10, 16 << 10, 18 << 10, 32 << 10, 36 << 10, 64 << 10, 72 << 10, 136 << 10} {
			at := edge - SealedSize(kt, 0) // the message whose bare file is edge bytes, were it one chunk
			for d := -12; d <= 3; d++ {
				sizes = append(sizes, at+d)
			}
		}
		sizes = append(sizes, len(sig)+1, len(sig)+300, ageChunk-300, ageChunk, ageChunk+300)
		for _, n := range sizes {
			if n <= len(sig) {
				continue // no message is shorter than its signature
			}
			line := append(bytes.Repeat([]byte{'e'}, n-len(sig)-1), '\n')
			p, sealed := Plaintext(line, sig, kt)
			if got := sealedLen(t, rs[kt], p); got != sealed {
				t.Fatalf("%s, a message of %d: age wrote %d bytes, Plaintext said %d", kt, n, got, sealed)
			}
			if sealed != PaddedSize(sealed) {
				t.Fatalf("%s, a message of %d: %d bytes is not a whole number of %d-byte blocks", kt, n, sealed, PadBlock(sealed))
			}
			// The least padding: the first block at or after the bare file.
			if want := PaddedSize(SealedSize(kt, n)); sealed != want {
				t.Fatalf("%s, a message of %d (%d bytes bare): padded to %d, want %d", kt, n, SealedSize(kt, n), sealed, want)
			}
			if !bytes.HasPrefix(p, append(bytes.Clone(line), sig...)) || strings.Trim(string(p[n:]), ".") != "" {
				t.Fatalf("%s, a message of %d: what is encrypted is not the line, the signature, then padding", kt, n)
			}
		}
	}
}

// What the padding is for: bodies of different lengths are one size on the
// wire. And where the first boundaries fall.
func TestShortBodiesAreOneSize(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	box, _, signer := passBox(t, now)
	sizeOf := func(kt KeyType, body string) int {
		e, err := NewEnvelope(box.id.Address(), Address{1}, body, now)
		if err != nil {
			t.Fatal(err)
		}
		e.Identity = box.id.Document()
		line, sig, err := SignEnvelope(e, signer)
		if err != nil {
			t.Fatal(err)
		}
		_, sealed := Plaintext(line, sig, kt)
		return sealed
	}
	for _, c := range []struct {
		kt     KeyType
		bodies []string
		size   int
	}{
		{PostQuantum, []string{"", "no", "yes", "reject", "approve", strings.Repeat("a", 188)}, 3072},
		{PostQuantum, []string{strings.Repeat("a", 189), strings.Repeat("a", 1212)}, 4096},
		{Classic, []string{"", "no", "yes", strings.Repeat("a", 623)}, 2048},
		{Classic, []string{strings.Repeat("a", 624), strings.Repeat("a", 1647)}, 3072},
	} {
		for _, b := range c.bodies {
			if got := sizeOf(c.kt, b); got != c.size {
				t.Errorf("%s, a body of %d bytes: %d on the wire, want %d", c.kt, len(b), got, c.size)
			}
		}
	}
}
