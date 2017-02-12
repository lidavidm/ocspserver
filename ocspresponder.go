package main

import (
	"encoding/hex"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"golang.org/x/crypto/ocsp"

	"github.com/cloudflare/cfssl/certdb"
	cfocsp "github.com/cloudflare/cfssl/ocsp"
)

// CertDbSource is an OCSP response Source backed by certdb.
// See the cfssl.ocsp.responder.Source interface.
type CertDbSource struct {
	Accessor certdb.Accessor
}

const interval = 96 * time.Hour

func NewSource(dbAccessor certdb.Accessor, caFile string, respFile string, respKey string) cfocsp.Source {

	go func() { // heavy join
		signer, err := cfocsp.NewSignerFromFile(caFile, respFile, respKey, interval)
		if err != nil {
			// TODO log it, this is bad.
			return
		}
		for {
			time.Sleep(5 * time.Second) // TODO decide what interval
			unexpired, err := dbAccessor.GetUnexpiredCertificates()
			if err != nil {
				return
			}
			for _, certRecord := range unexpired {
				ocsps, err := dbAccessor.GetOCSP(certRecord.Serial, certRecord.AKI)
				if err != nil {
					return
				}
				for _, ocsp := range ocsps {
					if ocsp.Expiry.After(time.Now()) {
						newExpiry := time.Now().Add(interval)
						cert, err := helpers.ParseCertificatePEM([]byte(certRecord.PEM)) // PEM is ASCII data

						if err != nil {
							// TODO: Decide what to do with this ocsp record
							continue
						}

						signReq := cfocsp.SignRequest{
							Certificate: cert,
							Status:      certRecord.Status,
						}

						if certRecord.Status == "revoked" {
							signReq.Reason = certRecord.Reason
							signReq.RevokedAt = certRecord.RevokedAt
						}

						resp, err := signer.Sign(signReq)
						if err != nil {
							// Unable to sign! fatal
							return
						}

						err = dbAccessor.UpsertOCSP(cert.SerialNumber.String(), hex.EncodeToString(cert.AuthorityKeyId), string(resp), newExpiry)
					}
				}
			}
		}
	}()
	return CertDbSource{
		Accessor: dbAccessor,
	}
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
