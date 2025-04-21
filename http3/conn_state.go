package http3

import (
	stdTls "crypto/tls"
	tls "github.com/metacubex/utls"
)

func convertConnState(state tls.ConnectionState) stdTls.ConnectionState {
	return stdTls.ConnectionState{
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
}
