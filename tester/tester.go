package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
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
	_, err = x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		log.Fatalln("could not parse certificate")
	}

	log.Println("Done")
}
