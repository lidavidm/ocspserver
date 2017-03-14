package main

import (
	"encoding/hex"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"golang.org/x/crypto/ocsp"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/log"
	cfocsp "github.com/cloudflare/cfssl/ocsp"
)

// CertDbSource is an OCSP response Source backed by certdb.
// See the cfssl.ocsp.responder.Source interface.
type CertDbSource struct {
	Accessor certdb.Accessor
}

func NewSource(dbAccessor certdb.Accessor, signer cfocsp.Signer, interval time.Duration, refreshFrequency time.Duration) cfocsp.Source {

	go func() { // heavy join
		for {
			time.Sleep(refreshFrequency)
			unexpired, err := dbAccessor.GetUnexpiredCertificates()
			if err != nil {
				log.Critical("could not access database: ", err)
				return
			}
			for _, certRecord := range unexpired {
				ocsps, err := dbAccessor.GetOCSP(certRecord.Serial, certRecord.AKI)
				if err != nil {
					log.Critical("could not access database: ", err)
					return
				}
				cert, err := helpers.ParseCertificatePEM([]byte(certRecord.PEM)) // PEM is ASCII data

				if err != nil {
					log.Critical("could not parse cert PEM: ", err)
					// TODO: Decide what to do with this certRecord
					continue
				}

				for _, ocsp := range ocsps {
					if !ocsp.Expiry.After(time.Now()) {
						continue
					}
					newExpiry := time.Now().Add(interval)

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
						log.Critical("could not sign OCSP response: ", err)
						return
					}

					err = dbAccessor.UpsertOCSP(cert.SerialNumber.String(), hex.EncodeToString(cert.AuthorityKeyId), string(resp), newExpiry)
					if err != nil {
						log.Critical("could not insert into database: ", err)
						return
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
