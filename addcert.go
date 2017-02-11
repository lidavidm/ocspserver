package main

import "net/http"

// This is patterned on
// https://github.com/cloudflare/cfssl/blob/master/api/revoke/revoke.go

// A Handler accepts new SSL certificates and inserts them into the
// certdb
type Handler struct {
}

func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	return nil
}
