package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/fullsailor/pkcs7"
)

var myPkcs7 pkcs7.PKCS7

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	// First element in os.Args is always the program name,
	// So we need at least 2 arguments to have a file name argument.
	if len(os.Args) < 2 {
		log.Fatal("ERROR: PDF file name not specified")
	}

	//Read the contents of the PDF file
	pdfFile, err := ioutil.ReadFile(os.Args[1])
	check(err)

	//Search the magic string which indicates a Signature inside the file
	magicString := "/ByteRange["
	index := bytes.Index(pdfFile, []byte(magicString))
	if index < 0 {
		log.Fatal("Signature not found")
	} else {
		fmt.Printf("Signature found at offset: %d\n", index)
	}

	//Parse the ByteRange numbers:
	//certIndex1, certIndex2, certIndex3
	offsetStart := index + len(magicString)
	offsetEnd := offsetStart + 40 //To be safe
	stringToParse := pdfFile[offsetStart:offsetEnd]

	var certIndex1 int
	var certIndex2 int
	var certIndex3 int

	fmt.Sscanf(string(stringToParse), "%d%d%d", &certIndex1, &certIndex2, &certIndex3)
	fmt.Printf("Idx1: %d\n", certIndex1)
	fmt.Printf("Idx2: %d\n", certIndex2)
	fmt.Printf("Idx3: %d\n", certIndex3)

	//The Signature is between the Index1 and Index2, without the first and last chars
	dataDER := pdfFile[certIndex2+1 : certIndex3-1]
	//And after removing trailing spaces
	dataDER = bytes.Trim(dataDER, "\x30")
	//And after converting into a string
	dataDER, err = hex.DecodeString(string(dataDER))
	check(err)

	//And build a new PDF removing the Signature
	contentPDF := pdfFile[0:certIndex2]
	contentPDF = append(contentPDF, pdfFile[certIndex3:]...)

	//Calculate the hash of the content with the SHA256 algorithm
	h := sha256.New()
	h.Write(contentPDF)
	hashedData := h.Sum(nil)

	//Print the hash
	fmt.Printf("Hash of the content of the PDF: %x\n", hashedData)

	fmt.Printf("Length of the contents of the PDF: %d\n", len(contentPDF))

	//Parse the SignedData as a PKCS#7 DER encoded package
	signaturePDF, err := pkcs7.Parse(dataDER)
	check(err)

	//Get the only signer certificate
	signerCertificate := signaturePDF.GetOnlySigner()
	if signerCertificate == nil {
		log.Fatal("There are more than one signer")
	}

	//Print some data about the signer, like her PublicKey and the SignatureAlgorithm used
	commonName := signerCertificate.Subject.CommonName
	publicKey := signerCertificate.PublicKey.(*rsa.PublicKey)
	signatureAlgorithm := signerCertificate.SignatureAlgorithm
	fmt.Println("The name of the signer:")
	spew.Dump(commonName)
	fmt.Println("The Public Key used to sign the document:")
	spew.Dump(publicKey)
	fmt.Println("The algorithm used to sign the document:")
	spew.Dump(signatureAlgorithm)

	//Get and print the encrypted digest of the PDF
	//	signerCero := signaturePDF.Signers[0]
	//	digestAlgorithm := signerCero.DigestAlgorithm
	//	digestEncryptionAlgorithm := signerCero.DigestEncryptionAlgorithm
	//	encryptedDigest := signerCero.EncryptedDigest

	//	fmt.Println("digestAlgorithm:")
	//	spew.Dump(digestAlgorithm)
	//	fmt.Println("digestEncryptionAlgorithm:")
	//	spew.Dump(digestEncryptionAlgorithm)
	//	fmt.Println("encryptedDigest:")
	//	spew.Dump(encryptedDigest)

	//Set the Content field of the SignaturePDF struct to the PDF contents
	signaturePDF.Content = contentPDF
	err = signaturePDF.Verify()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n\n***********************************************")
	fmt.Println("**** The signature has been verified!!!! ******")
	fmt.Println("***********************************************")

}
