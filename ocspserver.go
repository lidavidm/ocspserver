package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/cloudflare/cfssl/api/revoke"
	"github.com/cloudflare/cfssl/certdb/dbconf"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/ocsp"
	_ "github.com/mattn/go-sqlite3"
)

func convertHandler(f http.Handler) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		f.ServeHTTP(w, r)
	}
}

func main() {
	apiFlag := flag.Bool("api", false, "Run the API server.")
	ocspFlag := flag.Bool("ocsp", false, "Run the OCSP responder.")
	dbConfigFlag := flag.String("db-config", "", "The certdb to use.")

	flag.Parse()

	if !*apiFlag && !*ocspFlag {
		log.Fatal("Exactly one of --api and --ocsp is required.")
	}

	db, err := dbconf.DBFromConfig(*dbConfigFlag)

	if err != nil {
		log.Fatal("Could not load certdb: ", err)
	}

	dbAccessor := sql.NewAccessor(db)

	if *apiFlag {
		http.Handle("/api/addCert", NewHandler(dbAccessor))
		http.Handle("/api/revokeCert", revoke.NewHandler(dbAccessor))
	} else {
		handler := ocsp.NewResponder(NewSource(dbAccessor, signer))
		http.Handle("/", http.StripPrefix("/", handler))
	}

	http.ListenAndServe("127.0.0.1:8080", nil)
}
