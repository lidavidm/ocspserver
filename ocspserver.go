package main

import (
	"flag"
	"log"
	"net/http"
	"time"

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
	refreshFreqFlag := flag.String("ocsp-refresh-freq", "15m", "The frequency at which to refresh OCSP responses in the database, as a duration string.")

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
		refreshFreq, err := time.ParseDuration(*refreshFreqFlag)
		if err != nil {
			log.Fatal("Could not parse interval duration string:", err)
		}
		handler := ocsp.NewResponder(NewSource(dbAccessor, signer, interval, refreshFreq))
		http.Handle("/", http.StripPrefix("/", handler))
	}

	http.ListenAndServe("127.0.0.1:8080", nil)
}
