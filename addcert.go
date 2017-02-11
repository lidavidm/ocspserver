package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/errors"
)

// This is patterned on
// https://github.com/cloudflare/cfssl/blob/master/api/revoke/revoke.go

// A Handler accepts new SSL certificates and inserts them into the
// certdb
type Handler struct {
	dbAccessor certdb.Accessor
}

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

	// TODO: validate request

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
