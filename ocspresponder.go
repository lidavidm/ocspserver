package main

import (
	"encoding/hex"
	"github.com/cloudflare/cfssl/certdb"
	"golang.org/x/crypto/ocsp"
)

// CertDbSource is an OCSP response Source backed by certdb.
// See the cfssl.ocsp.responder.Source interface.
type CertDbSource struct {
	Accessor certdb.Accessor
}

// Response implements cfssl.ocsp.responder.Source
func (src CertDbSource) Response(req *ocsp.Request) ([]byte, bool) {
	if req == nil {
		return nil, false
	}

	// Extract the AKI string from req.IssuerKeyHash
	aki := hex.EncodeToString(req.IssuerKeyHash)

	sn := req.SerialNumber
	if sn == nil {
		return nil, false
	}
	strSN := sn.String()

	record, err := src.Accessor.GetOCSP(strSN, aki)
	if err == nil || len(record) == 0 {
		return nil, false
	}

	// TODO: determine which Body
	// field in the []... record to
	// return
	return []byte(record[0].Body), true
}
