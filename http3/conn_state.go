package http3

import (
	stdTls "crypto/tls"
	"reflect"
	"unsafe"

	tls "github.com/metacubex/utls"
)

var stdekmOffset = mustOK(reflect.TypeOf((*stdTls.ConnectionState)(nil)).Elem().FieldByName("ekm")).Offset
var ekmOffset = mustOK(reflect.TypeOf((*tls.ConnectionState)(nil)).Elem().FieldByName("ekm")).Offset

func mustOK[T any](result T, ok bool) T {
	if ok {
		return result
	}
	panic("operation failed")
}

func convertConnState(state tls.ConnectionState) stdTls.ConnectionState {
	stdState := stdTls.ConnectionState{
		Version:                    state.Version,
		HandshakeComplete:          state.HandshakeComplete,
		CipherSuite:                state.CipherSuite,
		NegotiatedProtocol:         state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual: state.NegotiatedProtocolIsMutual,
		ServerName:                 state.ServerName,
		PeerCertificates:           state.PeerCertificates,
		VerifiedChains:             state.VerifiedChains,
		OCSPResponse:               state.OCSPResponse,
		TLSUnique:                  state.TLSUnique,
	}
	// The layout of map, chan, and func types is equivalent to *T.
	// state.ekm is a func(label string, context []byte, length int) ([]byte, error)
	*(*unsafe.Pointer)(unsafe.Add(unsafe.Pointer(&stdState), stdekmOffset)) = *(*unsafe.Pointer)(unsafe.Add(unsafe.Pointer(&state), ekmOffset))
	return stdState
}
