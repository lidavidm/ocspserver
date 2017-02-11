package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
)

func prepDB() (certdb.Accessor, error) {
	// TODO: when integrating with CFSSL, use the DB already in
	// the repository
	db := testdb.SQLiteDB("testdata/certstore_development.db")
	dbAccessor := sql.NewAccessor(db)

	return dbAccessor, nil
}

func makeRequest(t *testing.T, req map[string]interface{}) (resp *http.Response, body []byte) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(NewHandler(dbAccessor))
	defer ts.Close()

	blob, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = http.Post(ts.URL, "application/json", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	return
}

func makeCertificate() (serialNumber *big.Int, cert *x509.Certificate, pemBytes []byte, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err = rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		return
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Cornell CS 5152"},
		},
		AuthorityKeyId: []byte{42, 42, 42, 42},
	}
	cert = &template

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)

	if err != nil {
		return
	}

	pemBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return
}

func TestInsertValidCertificate(t *testing.T) {
	serialNumber, cert, pemBytes, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "good",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatal("Expected HTTP OK, got", resp.StatusCode, string(body))
	}
}

func TestInsertMissingSerial(t *testing.T) {
	_, cert, pemBytes, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, map[string]interface{}{
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "good",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}

func TestInsertMissingAKI(t *testing.T) {
	serialNumber, _, pemBytes, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, map[string]interface{}{
		"serial_number": serialNumber.Text(16),
		"status":        "good",
		"pem":           string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}

func TestInsertMissingPEM(t *testing.T) {
	serialNumber, cert, _, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "good",
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}

func TestInsertInvalidSerial(t *testing.T) {
	_, cert, pemBytes, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, map[string]interface{}{
		"serial_number":            "this is not a serial number",
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "good",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}

func TestInsertInvalidAKI(t *testing.T) {
	serialNumber, _, pemBytes, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": "this is not an AKI",
		"status":                   "good",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request, got", resp.StatusCode, string(body))
	}
}

func TestInsertInvalidStatus(t *testing.T) {
	serialNumber, cert, pemBytes, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "invalid",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}

func TestInsertInvalidPEM(t *testing.T) {
	serialNumber, cert, _, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "good",
		"pem":                      "this is not a PEM certificate",
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request, got", resp.StatusCode, string(body))
	}
}

func TestInsertWrongSerial(t *testing.T) {
	_, cert, pemBytes, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, map[string]interface{}{
		"serial_number":            big.NewInt(1).Text(16),
		"authority_key_identifier": hex.EncodeToString(cert.AuthorityKeyId),
		"status":                   "good",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}

func TestInsertWrongAKI(t *testing.T) {
	serialNumber, _, pemBytes, err := makeCertificate()

	if err != nil {
		t.Fatal(err)
	}

	resp, body := makeRequest(t, map[string]interface{}{
		"serial_number":            serialNumber.Text(16),
		"authority_key_identifier": hex.EncodeToString([]byte{7, 7}),
		"status":                   "good",
		"pem":                      string(pemBytes),
	})

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("Expected HTTP Bad Request", resp.StatusCode, string(body))
	}
}
