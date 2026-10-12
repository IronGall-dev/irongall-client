package protocol

import (
	"errors"
	"strings"
)

// Padding. The server sees each message's ciphertext, and so its size. A
// sender pads every envelope, with its pad member, so that the ciphertext is
// a whole number of blocks: the server then learns a message's size to within
// one block, and no more.
//
// The block is 1/16 of the ciphertext's size, rounded up to a power of two,
// and never under 1 KiB: 1 KiB blocks up to 16 KiB, 2 KiB up to 32 KiB, 4 KiB
// up to 64 KiB, and on. That is 16 possible sizes up to 16 KiB and 8 for each
// doubling after, at a cost of about 1/8 of the message at most.
//
// It is the ciphertext that is measured, because the ciphertext is what the
// server sees and what its size limit counts. age adds a fixed number of
// bytes for a key type and a plaintext length ([SealedSize]), so the pad is
// computed, and the sender then checks the size of what age wrote.

const (
	// PadMinBlock is the smallest block, in bytes.
	PadMinBlock = 1024
	// padMember is what the pad member costs beside its filler: ,"pad":""
	padMember = 9
	// padFiller is one byte of filler: ASCII that JSON never escapes, so a
	// pad of n of them is n bytes.
	padFiller = "."

	// An age file is a header, a 16-byte nonce, and the plaintext in chunks
	// of 64 KiB, each followed by a 16-byte tag. A file always has one chunk,
	// and its last chunk is never empty unless it is the only one.
	ageNonce = 16
	ageChunk = 64 << 10
	ageTag   = 16
	// The header's size for one recipient of each key type. It never varies:
	// its fields are fixed-size values in unpadded base64.
	ageHeaderClassic     = 168
	ageHeaderPostQuantum = 1627
)

func ageHeader(t KeyType) int {
	if t == PostQuantum {
		return ageHeaderPostQuantum
	}
	return ageHeaderClassic
}

// SealedSize returns the size of the age file that holds plaintext bytes
// encrypted to one key of type t.
func SealedSize(t KeyType, plaintext int) int {
	chunks := max(1, (plaintext+ageChunk-1)/ageChunk)
	return ageHeader(t) + ageNonce + plaintext + chunks*ageTag
}

// plaintextSize returns the plaintext length whose age file, to a key of type
// t, is sealed bytes, and whether there is one: no file is under the header's
// size, and none is 1 to 16 bytes past a file that ends on a full chunk.
func plaintextSize(t KeyType, sealed int) (int, bool) {
	body := sealed - ageHeader(t) - ageNonce // the chunks, with their tags
	chunks := max(1, (body+ageChunk+ageTag-1)/(ageChunk+ageTag))
	n := body - chunks*ageTag
	return n, n >= 0 && SealedSize(t, n) == sealed
}

// PadBlock returns the block a ciphertext of size bytes is padded to a
// multiple of: the smallest power of two that is at least size/16, and never
// under [PadMinBlock].
func PadBlock(size int) int {
	block := PadMinBlock
	for 16*block < size {
		block *= 2
	}
	return block
}

// PaddedSize returns the smallest size, at least size, that is a multiple of
// its own block: what a ciphertext of size bytes is padded to. A size it
// returns is padded to itself.
func PaddedSize(size int) int {
	block := PadBlock(size)
	return (size + block - 1) / block * block
}

// padTo returns what an envelope of bare bytes, marshalled with no pad member,
// is padded to for a key of type t: the size of its age file, and the filler
// its pad member takes. Every envelope carries the member, which costs
// padMember bytes beside its filler, so the file is the next whole number of
// blocks at or after the envelope's with an empty pad.
func padTo(t KeyType, bare int) (sealed, filler int) {
	sealed = PaddedSize(SealedSize(t, bare+padMember))
	for {
		if n, ok := plaintextSize(t, sealed); ok {
			return sealed, n - bare - padMember
		}
		// No age file has this size: the next block. Under 3 GiB every
		// padded size is a file's (TestEveryPaddedSizeIsAnAgeFile).
		sealed = PaddedSize(sealed + 1)
	}
}

// MarshalPadded returns the envelope as [Envelope.Marshal] does, with a pad
// member whose filler makes the age file holding it, encrypted to one key of
// type t, a whole number of blocks; and that file's size. Whatever Pad held
// is replaced. Every envelope gets the member, with no filler when none is
// needed: so every file is on a block, and what padding costs at a size limit
// is the member's 9 bytes and no more.
//
// The caller encrypts what it returns, and checks the file's size is sealed.
func (e *Envelope) MarshalPadded(t KeyType) (plaintext []byte, sealed int, err error) {
	bare, err := e.marshal(nil)
	if err != nil {
		return nil, 0, err
	}
	sealed, n := padTo(t, len(bare))
	filler := strings.Repeat(padFiller, n)
	plaintext, err = e.marshal(&filler)
	if err != nil {
		return nil, 0, err
	}
	if len(plaintext) != len(bare)+padMember+n {
		return nil, 0, errors.New("the padded envelope is not the size its pad was computed for")
	}
	return plaintext, sealed, nil
}
