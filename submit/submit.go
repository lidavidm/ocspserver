package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"

	"flag"

	"github.com/cloudflare/cfssl/helpers"
	ct "github.com/google/certificate-transparency/go"
	logclient "github.com/google/certificate-transparency/go/client"
	"github.com/google/certificate-transparency/go/jsonclient"

	_ "github.com/mattn/go-sqlite3"
)

func makeCertificate(root *x509.Certificate, rootKey crypto.Signer) ([]byte, error) {
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Cornell CS 5152"},
		},
		AuthorityKeyId: []byte{42, 42, 42, 42},
	}
	// // Generate a CA certificate
	// issuerTemplate := x509.Certificate{
	// 	SerialNumber: issuerSerial,
	// 	Subject: pkix.Name{
	// 		Organization: []string{"Cornell CS 5152"},
	// 	},
	// 	AuthorityKeyId: []byte{42, 42, 42, 42},
	// 	KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	// 	IsCA:           true,
	// 	BasicConstraintsValid: true,
	// }
	return x509.CreateCertificate(rand.Reader, &template, root, rootKey.Public(), rootKey)
}

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
	logclient, err := logclient.New("http://localhost:6962", client, options)
	if err != nil {
		log.Fatal(err)
	}

	// Get the accepted roots
	roots, err := logclient.GetAcceptedRoots(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if roots == nil {
		log.Fatal("No accepted roots?")
	}
	fmt.Println(roots)

	// certdata, err := ioutil.ReadFile("/home/lidavidm/Code/gohome/src/github.com/google/trillian/testdata/int-ca.cert")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// certchain := testonly.CertsFromPEM(certdata)
	// sct, err := logclient.AddChain(ctx, certchain)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.Println(sct)

	rootData, err := ioutil.ReadFile("fake-ca.cert")
	if err != nil {
		log.Fatal(err)
	}
	root, err := helpers.ParseCertificatePEM(rootData)
	if err != nil {
		log.Fatal(err)
	}

	rootKeyData, err := ioutil.ReadFile("fake-ca.privkey.pem")
	if err != nil {
		log.Fatal(err)
	}
	rootKey, err := helpers.ParsePrivateKeyPEMWithPassword(rootKeyData, []byte("gently"))
	if err != nil {
		log.Fatal(err)
	}

	cert, err := makeCertificate(root, rootKey)
	if err != nil {
		log.Fatal(err)
	}
	sct, err := logclient.AddChain(ctx, []ct.ASN1Cert{{Data: cert}})
	log.Println(sct)

	// _, err = logclient.AddChain(ctx, []ct.ASN1Cert{{Data: root.Raw}})
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// log.Print("Opening db...")
	// db, err := dbconf.DBFromConfig(dbConfig)
	// if err != nil {
	// 	log.Print(dbConfig)
	// 	log.Fatal("Could not load certdb: ", err, dbConfig)
	// }

	// log.Print("Creating certdb...")
	// dbAccessor := sql.NewAccessor(db)

	// log.Print("Getting certificates...")
	// certs, err := dbAccessor.GetUnexpiredCertificates()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// for _ = range certs {
	// 	log.Print("Submitting a cert...")
	// 	logclient.AddChain(ctx, nil)
	// }
}
