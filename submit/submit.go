package main

import (
	"context"
	"log"
	"net/http"

	"flag"

	"github.com/cloudflare/cfssl/certdb/dbconf"
	"github.com/cloudflare/cfssl/certdb/sql"
	logclient "github.com/google/certificate-transparency/go/client"
	"github.com/google/certificate-transparency/go/jsonclient"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	var host string
	var dbConfig string
	flag.StringVar(&host, "host", "localhost:6962", "The URL to the CT server.")
	flag.StringVar(&dbConfig, "dbConfig", "", "The certdb config path.")

	flag.Parse()

	client := http.DefaultClient
	options := jsonclient.Options{}
	ctx := context.Background()

	log.Print("Creating client...")
	logclient, err := logclient.New("localhost:6962", client, options)
	if err != nil {
		log.Fatal(err)
	}

	log.Print("Opening db...")
	db, err := dbconf.DBFromConfig(dbConfig)
	if err != nil {
		log.Print(dbConfig)
		log.Fatal("Could not load certdb: ", err, dbConfig)
	}

	log.Print("Creating certdb...")
	dbAccessor := sql.NewAccessor(db)

	log.Print("Getting certificates...")
	certs, err := dbAccessor.GetUnexpiredCertificates()
	if err != nil {
		log.Fatal(err)
	}

	for _ = range certs {
		log.Print("Submitting a cert...")
		logclient.AddChain(ctx, nil)
	}
}
