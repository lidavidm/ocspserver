package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/crypto/ocsp"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: tester certificate.pem")
		os.Exit(0)
	}
	pemBytes, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("could not find file: %v", os.Args[1])
	}
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		log.Fatalln("could not decode certificate file")
	}
	pCertificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		log.Fatalln("could not parse certificate")
	}
	req, err := ocsp.CreateRequest(pCertificate, pCertificate, nil)
	if err != nil {
		log.Fatalln("could not create request")
	}
	encoded := url.QueryEscape(base64.StdEncoding.EncodeToString(req))
	getReq, err := http.NewRequest("GET", "http://127.0.0.1:8080/"+encoded, bytes.NewBuffer(nil))
	if err != nil {
		log.Fatalln("could not create GET request")
	}
	getReq.Header.Set("Content-Type", "application/ocsp-request")
	var cli http.Client
	resp, err := cli.Do(getReq)
	if err != nil {
		log.Fatalln("no GET response", err)
	}
	defer resp.Body.Close()
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln("could not read the GET response")
	}
	pResponse, err := ocsp.ParseResponse(respData, pCertificate)
	if err != nil {
		log.Fatalln("could not parse the ocsp response: %v", err)
	}
	switch pResponse.Status {
	case ocsp.Good:
		log.Println("Good")
	case ocsp.Revoked:
		log.Println("Revoked")
	case ocsp.Unknown:
		log.Println("Unknown")
	}
}
