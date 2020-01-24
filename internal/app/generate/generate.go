package generate

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli"
)

type Files struct {
	prvWriter *os.File
	pubWriter *os.File
}

type Keys struct {
	privateKey *rsa.PrivateKey
	publicKey  crypto.PublicKey
}

// Generate RSA public and private keys in PEM format
func GenerateKeys(c *cli.Context) error {
	// validate
	if err := validateKeys(c); err != nil {
		return err
	}
	// open files
	files, err := openFiles(c)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("unable to create file %q\n", err), 2)
	}
	// generate and write to files
	keys, err := getKeys()
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("unable to generate key %q\n", err), 2)
	}
	pubCont, err := x509.MarshalPKIXPublicKey(keys.publicKey)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("unable to marshall private key %q\n", err), 2)
	}
	prvPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keys.privateKey),
	}
	pubPem := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubCont,
	}
	if err := pem.Encode(files.prvWriter, prvPem); err != nil {
		return cli.NewExitError(fmt.Sprintf("unable to write private key %q\n", err), 2)
	}
	if err := pem.Encode(files.pubWriter, pubPem); err != nil {
		return cli.NewExitError(fmt.Sprintf("unable to write public key %q\n", err), 2)
	}
	return nil
}

func validateKeys(c *cli.Context) error {
	if !c.IsSet("public") {
		return cli.NewExitError("public key output file is not provided", 2)
	}
	if !c.IsSet("private") {
		return cli.NewExitError("private key output file is not provided", 2)
	}
	return nil
}

func Close(c io.Closer) error {
	err := c.Close()
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("unable to write public key %q\n", err), 2)
	}
	return err
}

func openFiles(c *cli.Context) (*Files, error) {
	f := &Files{}
	prvWriter, err := os.Create(c.String("private"))
	defer Close(prvWriter)
	if err != nil {
		return f, cli.NewExitError(fmt.Sprintf("unable to create private key file %q\n", err), 2)
	}
	pubWriter, err := os.Create(c.String("public"))
	defer Close(pubWriter)
	if err != nil {
		return f, cli.NewExitError(fmt.Sprintf("unable to create public key file %q\n", err), 2)
	}
	f.prvWriter = prvWriter
	f.pubWriter = pubWriter
	return f, nil
}

func getKeys() (*Keys, error) {
	k := &Keys{}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return k, cli.NewExitError(fmt.Sprintf("error in generating private key %q\n", err), 2)
	}
	if err := private.Validate(); err != nil {
		return k, cli.NewExitError(fmt.Sprintf("error in validating private key %q\n", err), 2)
	}
	public := private.Public()
	k.privateKey = private
	k.publicKey = public
	return k, nil
}
