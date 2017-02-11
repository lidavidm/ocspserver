package main

import (
	"encoding/hex"
	"github.com/cloudflare/cfssl/certdb"
	"golang.org/x/crypto/ocsp"
)

// CertDbSource ... TODO
// An OCSP response source backed by certdb. See
// cfssl.ocsp.responder.Source.
// NOTE: implements the cfssl.ocsp.responder.Source interface
type CertDbSource struct {
	// Write an implementation of ocsp.responder.Source that fetches an OCSP
	// response from an instance of certdb
	Accessor certdb.Accessor
}

// Response ... TODO
func (src CertDbSource) Response(req *ocsp.Request) ([]byte, bool) {
	if req == nil {
		return nil, false
	}
	// Extract the AKI string from req.IssuerKeyHash
	akiByte := make([]byte, len(req.IssuerKeyHash))
	_, err := hex.Decode(akiByte, req.IssuerKeyHash)
	if err == nil {
		return nil, false
	}
	aki := string(akiByte)
	var strSN string
	sn := req.SerialNumber
	if sn == nil {
		return nil, false
	}
	strSN = sn.String()
	record, err := src.Accessor.GetOCSP(strSN, aki)
	if err == nil {
		return nil, false
	}
	if len(record) == 0 {
		return nil, false
	}
	// TODO: determine which Body
	// field in the []... record to
	// return
	return []byte(record[0].Body), true
}
