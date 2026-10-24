package handshake

import (
	"bytes"
	"slices"
	"testing"
)

// Chrome's trust_anchors extension is sent raw. Its body is a 16-bit list length followed by
// 8-bit length-prefixed relative OIDs, sorted so the fingerprint is stable (upstream
// v0.61.0-sing-box-mod.11).
func TestChromeTrustAnchorsEncoding(t *testing.T) {
	ids := [][]byte{
		{0xd6, 0x79, 0x09, 0x0f},
		{0x82, 0xdf, 0x13, 0x02, 0x01},
		{0xd6, 0x79, 0x09, 0x01},
	}
	original := slices.Clone(ids)
	encoded := encodeTrustAnchorIDs(ids)

	if !slices.Equal(ids[0], original[0]) || !slices.Equal(ids[1], original[1]) || !slices.Equal(ids[2], original[2]) {
		t.Fatal("encoding reordered or mutated the caller's IDs")
	}
	if len(encoded) < 2 {
		t.Fatal("encoded extension is too short for its length prefix")
	}
	listLength := int(encoded[0])<<8 | int(encoded[1])
	if listLength != len(encoded)-2 {
		t.Fatalf("list length %d does not match body %d", listLength, len(encoded)-2)
	}

	offset := 2
	var decoded [][]byte
	for offset < len(encoded) {
		idLength := int(encoded[offset])
		offset++
		if offset+idLength > len(encoded) {
			t.Fatalf("ID length %d overruns the body at %d", idLength, offset)
		}
		decoded = append(decoded, slices.Clone(encoded[offset:offset+idLength]))
		offset += idLength
	}
	if len(decoded) != len(ids) {
		t.Fatalf("decoded %d IDs, want %d", len(decoded), len(ids))
	}
	for i := 1; i < len(decoded); i++ {
		if bytes.Compare(decoded[i-1], decoded[i]) > 0 {
			t.Fatalf("IDs are not sorted at %d: %x > %x", i, decoded[i-1], decoded[i])
		}
	}
	for _, id := range ids {
		found := false
		for _, got := range decoded {
			if slices.Equal(id, got) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("ID %x missing from the encoding", id)
		}
	}

	if extensionTrustAnchors != 0xca34 {
		t.Fatalf("trust_anchors extension ID = %#x, want 0xca34", extensionTrustAnchors)
	}
	if len(chromeTrustAnchorsData) == 0 {
		t.Fatal("Chrome trust anchor data is empty")
	}
}
