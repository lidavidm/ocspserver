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

// Response implements cfssl.ocsp.responder.Source, returning the OCSP response
// with the expiration date furthest in the future
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

	records, err := src.Accessor.GetOCSP(strSN, aki)
	if err == nil || len(records) == 0 {
		return nil, false
	}

	// Find the OCSPRecord with the expiration date furthest in the future
	cur := records[0]
	for _, rec := range records {
		if rec.Expiry.After(cur.Expiry) {
			cur = rec
		}
	}
	return []byte(cur.Body), true
}
