package quic

import (
	"testing"

	"github.com/sagernet/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

// The hard ceiling exists because InitialPacketSize cannot express two different
// things at once: a size the caller PREFERS, which legitimate fingerprint work may
// replace, and a size the PATH cannot exceed, which nothing may replace.
//
// These tests are written against populateConfig rather than against a live
// connection because populateConfig is where the order is decided; the order is
// the entire feature. A ceiling applied anywhere before the ChromeParrot branch
// is silently discarded for hysteria2's default configuration, and a test that
// only checks "a ceiling was set" would pass against that bug.

// ceilingCase is one row of the decision table: what goes in, and what the
// connection will then start at.
type ceilingCase struct {
	name         string
	configured   uint16
	ceiling      uint16
	chromeParrot bool
	want         uint16
	why          string
}

// expectedWithoutCeiling is the behaviour every case must keep when no ceiling is
// set, expressed as its own table so the ceiling rows cannot quietly redefine it.
var noCeilingCases = []ceilingCase{
	{
		name: "ChromeParrot off keeps the configured size", configured: 1232,
		want: 1232, why: "no override is in play, so the caller's value is the value",
	},
	{
		name: "ChromeParrot on replaces the configured size", configured: 1232, chromeParrot: true,
		want: chromeInitialPacketSize,
		why:  "the fingerprint contract predates the ceiling and must survive it",
	},
	{
		name: "ChromeParrot on with nothing configured", chromeParrot: true,
		want: chromeInitialPacketSize, why: "the same, from the default rather than from a value",
	},
	{
		name: "ChromeParrot off with nothing configured", want: protocol.InitialPacketSize,
		why: "the library default, unchanged",
	},
}

// ceilingCases is the table the feature is judged by. Every row names the number
// the connection will use, so a reviewer can check the claim rather than the code.
var ceilingCases = []ceilingCase{
	{
		name: "a ceiling below the fingerprint size wins", configured: 1232, ceiling: 1232, chromeParrot: true,
		want: 1232,
		why: "this is the case the whole change exists for: ChromeParrot would emit 1250 into a path " +
			"proven to carry 1232",
	},
	{
		name: "a ceiling above the fingerprint size does not raise it", configured: 1232, ceiling: 1252,
		chromeParrot: true, want: chromeInitialPacketSize,
		why: "a ceiling is a maximum, not a target: the fingerprint size is already inside it and is kept",
	},
	{
		name: "a ceiling below the fingerprint size with nothing configured", ceiling: 1232,
		chromeParrot: true, want: 1232,
		why: "the ceiling is the only size information available and it is a constraint, so it supplies the value",
	},
	{
		name: "a ceiling no lower than the configured value leaves it alone", configured: 1250, ceiling: 1252,
		chromeParrot: true, want: chromeInitialPacketSize,
		why: "nothing needs clamping; 1250 <= 1252",
	},
	{
		name: "a ceiling below the configured value clamps it", configured: 1250, ceiling: 1200,
		chromeParrot: true, want: 1200,
		why: "the constraint is honoured even though the caller asked for more",
	},
	{
		name: "a ceiling applies without ChromeParrot too", configured: 1400, ceiling: 1232,
		want: 1232,
		why:  "the ceiling is not a ChromeParrot feature; a non-parroting client has the same path",
	},
	{
		name: "a ceiling above the library default does not raise it", ceiling: 1452,
		want: protocol.InitialPacketSize,
		why:  "again a maximum, not a target",
	},
	{
		name: "the minimum legal packet size survives as a ceiling", configured: 1250, ceiling: 1200,
		want: 1200,
		why:  "1200 is the smallest an Initial packet may be, so it is a usable ceiling",
	},
}

func TestInitialPacketSizeCeilingIsAppliedAfterChromeParrot(t *testing.T) {
	for _, testCase := range append(append([]ceilingCase{}, noCeilingCases...), ceilingCases...) {
		t.Run(testCase.name, func(t *testing.T) {
			config := &Config{
				InitialPacketSize:        testCase.configured,
				InitialPacketSizeCeiling: testCase.ceiling,
				ChromeParrot:             testCase.chromeParrot,
			}
			populated := populateConfig(config)
			require.Equal(t, testCase.want, populated.InitialPacketSize,
				"with initial_packet_size=%d, ceiling=%d, ChromeParrot=%v: %s",
				testCase.configured, testCase.ceiling, testCase.chromeParrot, testCase.why)
		})
	}
}

// TestInitialPacketSizeCeilingSurvivesClone covers the field-copy hazard the
// ceiling shares with every other Config field: Clone is a shallow struct copy
// today, so it carries the ceiling, but a future hand-written copy that forgets
// it would silently drop a correctness constraint. This fails if that happens.
func TestInitialPacketSizeCeilingSurvivesClone(t *testing.T) {
	original := &Config{InitialPacketSizeCeiling: 1232}
	cloned := original.Clone()
	require.Equal(t, uint16(1232), cloned.InitialPacketSizeCeiling,
		"a Clone that drops the ceiling turns a proven path constraint into a preference")
}

// TestInitialPacketSizeCeilingSurvivesTheReturnedConfig pins that
// populateConfig's hand-written literal carries the field. The literal lists
// every field explicitly, so a new field is exactly the kind of thing it drops.
func TestInitialPacketSizeCeilingSurvivesTheReturnedConfig(t *testing.T) {
	populated := populateConfig(&Config{InitialPacketSizeCeiling: 1232})
	require.Equal(t, uint16(1232), populated.InitialPacketSizeCeiling)
}

// TestNoCeilingIsTheZeroValue keeps the compatibility promise explicit: a caller
// that never heard of the ceiling - which is every existing caller - gets exactly
// the old behaviour.
func TestNoCeilingIsTheZeroValue(t *testing.T) {
	require.Equal(t, uint16(0), (&Config{}).InitialPacketSizeCeiling)
	for _, testCase := range noCeilingCases {
		populated := populateConfig(&Config{
			InitialPacketSize: testCase.configured,
			ChromeParrot:      testCase.chromeParrot,
		})
		require.Equal(t, testCase.want, populated.InitialPacketSize, testCase.why)
	}
}

func TestClampToInitialPacketSizeCeiling(t *testing.T) {
	cases := []struct {
		name       string
		packetSize uint16
		ceiling    uint16
		want       uint16
	}{
		{"no ceiling leaves the size alone", 1250, 0, 1250},
		{"a size inside the ceiling is kept", 1200, 1232, 1200},
		{"a size equal to the ceiling is kept", 1232, 1232, 1232},
		{"a size above the ceiling is lowered", 1250, 1232, 1232},
		{"a zero size with a ceiling yields zero so the default still applies", 0, 1232, 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want,
				clampToInitialPacketSizeCeiling(testCase.packetSize, testCase.ceiling))
		})
	}
}

// TestMaxGrowablePacketSizeHonoursTheCeiling covers the second half of the
// ceiling: path MTU discovery grows the packet size upward after the handshake
// (measured 1232 -> 1438 on a real loopback path), so a connection that honoured
// its ceiling only for the first flight would exceed it shortly afterwards.
func TestMaxGrowablePacketSizeHonoursTheCeiling(t *testing.T) {
	cases := []struct {
		name      string
		ceiling   uint16
		peerLimit protocol.ByteCount
		want      protocol.ByteCount
	}{
		{
			name: "no ceiling keeps the peer's limit", ceiling: 0, peerLimit: 1452,
			want: 1452,
		},
		{
			name:    "a ceiling below the peer's limit lowers the growth ceiling",
			ceiling: 1232, peerLimit: 1452, want: 1232,
		},
		{
			name:    "a ceiling above the peer's limit changes nothing",
			ceiling: 1400, peerLimit: 1232, want: 1232,
		},
		{
			name:    "a ceiling equal to the peer's limit changes nothing",
			ceiling: 1232, peerLimit: 1232, want: 1232,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := &Config{InitialPacketSizeCeiling: testCase.ceiling}
			require.Equal(t, testCase.want, config.maxGrowablePacketSize(testCase.peerLimit))
		})
	}
}
