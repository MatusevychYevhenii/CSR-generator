package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"unicode/utf8"
)

// CreateDirIfNotExist create dir for ssl with key and csr
func CreateDirIfNotExist(dir string) bool {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			panic(err)
		}
		return true
	}
	return false
}

// TrimFirstRune remove first + 1 characters from string
func TrimFirstRune(s string) string {
	_, i := utf8.DecodeRuneInString(s)
	return s[i+1:]
}

func WriteCertInFile(domainFolder string, csrBytes []byte, keyBytes *rsa.PrivateKey) {
	result := CreateDirIfNotExist(domainFolder)

	if result == false {
		fmt.Println(domainFolder, "directory already exists! Exit!")
		os.Exit(3)
	}

	fmt.Println(domainFolder, "directory created: ", result)

	err := os.Chdir(domainFolder)
	if err != nil {
		panic(err)
	}

	certOut, _ := os.Create(domainFolder + ".csr")

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	certOut.Close()
	log.Print("written csr\n")

	keyOut, _ := os.OpenFile(domainFolder+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyBytes)})
	keyOut.Close()
	log.Print("written key\n")
}

// GenerateCert create ssl
func GenerateCert(domain string) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	emailAddress := "sys@appflame.com"
	oidEmailAddress := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	subj := pkix.Name{
		CommonName:         domain,
		Country:            []string{""},
		Province:           []string{""},
		Locality:           []string{""},
		Organization:       []string{""},
		OrganizationalUnit: []string{""},
	}
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)

	if string(domain[0]) == "*" {
		domainFolder := TrimFirstRune(domain)
		WriteCertInFile(domainFolder, csrBytes, keyBytes)
	} else {
		WriteCertInFile(domain, csrBytes, keyBytes)
	}

}

// main
func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage : %s <directory>\n", os.Args[0])
		os.Exit(0)
	}

	domain := os.Args[1]

	GenerateCert(domain)
}
