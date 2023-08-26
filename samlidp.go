// Package main contains an example identity provider implementation.
package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/url"

	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
)

//go:embed certs/*
var certs embed.FS

func loadKey() crypto.PrivateKey {
	keyBytes, err := certs.ReadFile("certs/key.pem")
	if err != nil {
		panic(fmt.Sprintf("failed to read key.pem: %v", err))
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		panic("failed to decode PEM from key.pem")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		panic(fmt.Sprintf("failed to parse private key: %v", err))
	}

	return key
}

func loadCrt() *x509.Certificate {
	crtBytes, err := certs.ReadFile("certs/certificate.pem")
	if err != nil {
		panic(fmt.Sprintf("failed to read certificate.pem: %v", err))
	}

	crtBlock, _ := pem.Decode(crtBytes)
	if crtBlock == nil {
		panic("failed to decode PEM from certificate.pem")
	}

	crt, err := x509.ParseCertificate(crtBlock.Bytes)
	if err != nil {
		panic(fmt.Sprintf("failed to parse certificate: %v", err))
	}

	return crt
}

func main() {
	logr := logger.DefaultLogger

	samlUrl, _ := url.Parse("https://saml.canonical.test")

	idpServer, err := samlidp.New(samlidp.Options{
		URL:         *samlUrl,
		Key:         loadKey(),
		Logger:      logr,
		Certificate: loadCrt(),
		Store:       &samlidp.MemoryStore{},
	})
	if err != nil {
		logr.Fatalf("%s", err)
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("ubuntu"), bcrypt.DefaultCost)
	err = idpServer.Store.Put("/users/ubuntu", samlidp.User{
		Name:           "ubuntu",
		HashedPassword: hashedPassword,
		Email:          "ubuntu@saml.caonical.test",
	})
	if err != nil {
		logr.Fatalf("%s", err)
	}

	http.Handle("/", idpServer)

	go func() {
		logr.Fatal(http.ListenAndServe(":80", nil))
	}()

	certFile, err := certs.ReadFile("certs/certificate.pem")
	if err != nil {
		panic(fmt.Sprintf("failed to read certificate.pem: %v", err))
	}

	keyFile, err := certs.ReadFile("certs/key.pem")
	if err != nil {
		panic(fmt.Sprintf("failed to read certificate.pem: %v", err))
	}

	cert, err := tls.X509KeyPair(certFile, keyFile)
	if err != nil {
		panic(fmt.Sprintf("failed to create X509 key pair: %v", err))
	}

	https := http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}
	logr.Fatal(https.ListenAndServeTLS("", ""))
}
