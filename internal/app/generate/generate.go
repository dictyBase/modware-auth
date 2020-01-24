package generate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli"
)

// Generate RSA public and private keys in PEM format
func GenerateKeys(c *cli.Context) error {
	// validate
	if err := validateKeys(c); err != nil {
		return err
	}
	// open files
	prvWriter, err := os.Create(c.String("private"))
	defer Close(prvWriter)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("unable to create private key file %q\n", err), 2)
	}
	pubWriter, err := os.Create(c.String("public"))
	defer Close(pubWriter)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("unable to create public key file %q\n", err), 2)
	}
	// generate and write to files
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("error in generating private key %q\n", err), 2)
	}
	if err := private.Validate(); err != nil {
		return cli.NewExitError(fmt.Sprintf("error in validating private key %q\n", err), 2)
	}
	prvPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(private),
	}
	public := private.Public()
	pubCont, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("unable to marshall private key %q\n", err), 2)
	}
	pubPem := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubCont,
	}
	if err := pem.Encode(prvWriter, prvPem); err != nil {
		return cli.NewExitError(fmt.Sprintf("unable to write private key %q\n", err), 2)
	}
	if err := pem.Encode(pubWriter, pubPem); err != nil {
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
