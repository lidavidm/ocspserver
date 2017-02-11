package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/ocsp"

	stdocsp "golang.org/x/crypto/ocsp"
)

// This is patterned on
// https://github.com/cloudflare/cfssl/blob/master/api/revoke/revoke.go

// A Handler accepts new SSL certificates and inserts them into the
// certdb
type Handler struct {
	dbAccessor certdb.Accessor
}

// Create a new Handler from a certdb.Accessor
func NewHandler(dbAccessor certdb.Accessor) http.Handler {
	return &api.HTTPHandler{
		Handler: &Handler{
			dbAccessor: dbAccessor,
		},
		Methods: []string{"POST"},
	}
}

type jsonAddRequest struct {
	Serial    string    `json:"serial_number"`
	AKI       string    `json:"authority_key_identifier"`
	CALabel   string    `json:"ca_label"`
	Status    string    `json:"status"`
	Reason    int       `json:"reason"`
	Expiry    time.Time `json:"expiry"`
	RevokedAt time.Time `json:"revoked_at"`
	PEM       string    `json:"pem"`
}

// Map of valid reason codes
var validReasons = map[int]bool{
	stdocsp.Unspecified:          true,
	stdocsp.KeyCompromise:        true,
	stdocsp.CACompromise:         true,
	stdocsp.AffiliationChanged:   true,
	stdocsp.Superseded:           true,
	stdocsp.CessationOfOperation: true,
	stdocsp.CertificateHold:      true,
	stdocsp.RemoveFromCRL:        true,
	stdocsp.PrivilegeWithdrawn:   true,
	stdocsp.AACompromise:         true,
}

func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	var req jsonAddRequest

	err = json.Unmarshal(body, &req)
	if err != nil {
		return errors.NewBadRequestString("Unable to parse certificate addition request")
	}

	if len(req.Serial) == 0 {
		return errors.NewBadRequestString("Serial number is required but not provided")
	}

	if len(req.AKI) == 0 {
		return errors.NewBadRequestString("Authority key identifier is required but not provided")
	}

	if _, present := ocsp.StatusCode[req.Status]; !present {
		return errors.NewBadRequestString("Invalid certificate status")
	}

	if _, present := validReasons[req.Reason]; !present {
		return errors.NewBadRequestString("Invalid certificate status reason code")
	}

	if len(req.PEM) == 0 {
		return errors.NewBadRequestString("The provided certificate is empty")
	}

	// Parse the certificate and validate that it matches
	block, _ := pem.Decode([]byte(req.PEM))
	if block == nil {
		return errors.NewBadRequestString("Unable to parse PEM encoded certificates")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.NewBadRequestString("Unable to parse certificates from PEM data")
	}

	serialBigInt := new(big.Int)
	if _, success := serialBigInt.SetString(req.Serial, 16); !success {
		return errors.NewBadRequestString("Unable to parse serial key of request")
	}

	if serialBigInt.Cmp(cert.SerialNumber) != 0 {
		return errors.NewBadRequestString("Serial key of request and certificate do not match")
	}

	aki, err := hex.DecodeString(req.AKI)
	if err != nil {
		return errors.NewBadRequestString("Unable to decode authority key identifier")
	}

	if !bytes.Equal(aki, cert.AuthorityKeyId) {
		return errors.NewBadRequestString("Authority key identifier of request and certificate do not match")
	}

	cr := certdb.CertificateRecord{
		Serial:    req.Serial,
		AKI:       req.AKI,
		CALabel:   req.CALabel,
		Status:    req.Status,
		Reason:    req.Reason,
		Expiry:    req.Expiry,
		RevokedAt: req.RevokedAt,
		PEM:       req.PEM,
	}

	err = h.dbAccessor.InsertCertificate(cr)
	if err != nil {
		return err
	}

	result := map[string]string{}
	return api.SendResponse(w, result)
}
