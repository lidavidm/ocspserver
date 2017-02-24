package main

import (
	"crypto/x509"
	"encoding/hex"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	cfocsp "github.com/cloudflare/cfssl/ocsp"
	"golang.org/x/crypto/ocsp"
	"os"
	"strings"
	"testing"
)

// Path to a test SQLite database (relative to the $GOPATH)
var dbRelPath = "/src/github.com/cloudflare/cfssl/certdb/testdb/certstore_development.db"

// TODO: redefine
type testCase struct {
	method, path string
	expected     int
}

func ocspRecordOfCert(cert *x509.Certificate) certdb.OCSPRecord {
	return certdb.OCSPRecord{
		Serial: cert.SerialNumber.String(),
		AKI:    hex.EncodeToString(cert.AuthorityKeyId),
		Expiry: cert.NotAfter,
	}
}

func TestCertDbResponse(t *testing.T) {
	// TODO: Don't rely on the test database in the testdb directory
	// TODO: Add tests for MySQL and PostgreSQL databases

	/*******************************************
	 * TODO: Create some database(s) for testing
	 *******************************************/

	// Get the url of a test database
	gopath := os.Getenv("GOPATH")
	if strings.Compare(gopath, "") == 0 {
		t.Error("$GOPATH environment variable is not set")
	}
	dbpath := gopath + dbRelPath

	// Create database and wrap it in a
	// "github.com/cloudflare/cfssl/certdb".Accessor
	db := testdb.SQLiteDB(dbpath)
	testdb.Truncate(db) // clear the database contents
	dbAccessor := sql.NewAccessor(db)

	/********************************************************************
	 * TODO: Create a bunch of x509.certificates and insert their
	 * corresponding OCSP responses into the database.
	 ********************************************************************/
	numcerts := 5
	certs := make([]*x509.Certificate, numcerts)
	for i := range certs {
		_, c, _, err := makeCertificate()
		if err != nil {
			t.Error(err)
		}
		certs[i] = c
		err = dbAccessor.InsertOCSP(ocspRecordOfCert(c))
		if err != nil {
			t.Error(err)
		}
		i++
	}

	// Wrap the database in a "github.com/cloudflare/cfssl/ocsp".Responder
	dbResponder := cfocsp.NewResponder(NewSource(dbAccessor))

	/********************************************************************
	 * TODO: Test that each certificate is found in the database.
	 *******************************************************************/
	for _, c := range certs {
		req := &ocsp.Request{
			IssuerKeyHash: c.AuthorityKeyId,
			SerialNumber:  c.SerialNumber,
		}
		_, found := dbResponder.Source.Response(req)
		if !found {
			t.Errorf("Certificate not found: %#v", req)
		}
	}
}
