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

func main() {
	apiFlag := flag.Bool("api", false, "Run the API server.")
	ocspFlag := flag.Bool("ocsp", false, "Run the OCSP responder.")
	dbConfigFlag := flag.String("db-config", "", "The certdb to use.")
	ocspIssuerFlag := flag.String("ocsp-issuer", "", "The OCSP issuer cert to use.")
	ocspResponderFlag := flag.String("ocsp-responder", "", "The OCSP responder cert to use.")
	ocspKeyFlag := flag.String("ocsp-responder-key", "", "The OCSP responder key to use.")
	ocspIntervalFlag := flag.String("oscp-interval", "60s", "The OCSP response validity interval, as a duration string (60s, 2h, etc).")

	flag.Parse()

	if !*apiFlag && !*ocspFlag {
		log.Fatal("Exactly one of --api and --ocsp is required.")
	}

	db, err := dbconf.DBFromConfig(*dbConfigFlag)

	if err != nil {
		log.Fatal("Could not load certdb: ", err)
	}

	dbAccessor := sql.NewAccessor(db)

	interval, err := time.ParseDuration(*ocspIntervalFlag)
	if err != nil {
		log.Fatal("Could not parse interval duration string:", err)
	}

	signer, err := ocsp.NewSignerFromFile(*ocspIssuerFlag, *ocspResponderFlag, *ocspKeyFlag, interval)
	if err != nil {
		log.Fatal("Could not create OCSP signer: ", err)
	}

	if *apiFlag {
		http.Handle("/api/addCert", NewHandler(dbAccessor, signer))
		http.Handle("/api/revokeCert", revoke.NewHandler(dbAccessor))
	} else {
		handler := ocsp.NewResponder(NewSource(dbAccessor))
		http.Handle("/", http.StripPrefix("/", handler))
	}

	http.ListenAndServe("127.0.0.1:8080", nil)
}
