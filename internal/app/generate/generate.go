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

type files struct {
	prvWriter *os.File
	pubWriter *os.File
}

type keyBytes struct {
	privateKey []byte
	publicKey  []byte
}

type encodeParams struct {
	prvWriter *os.File
	pubWriter *os.File
	prvPem    *pem.Block
	pubPem    *pem.Block
}

// Generate RSA public and private keys in PEM format
func GenerateKeys(c *cli.Context) error {
	// validate
	if err := validateKeys(c); err != nil {
		return err
	}
	f, err := buildFiles(c)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("error building files %q", err), 2)
	}
	if err := encodeFiles(f); err != nil {
		return cli.NewExitError(fmt.Sprintf("unable to write keys %q", err), 2)
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
		return fmt.Errorf("unable to write public key %q", err)
	}
	return err
}

func openFiles(c *cli.Context) (*files, error) {
	f := &files{}
	prvWriter, err := os.Create(c.String("private"))
	defer Close(prvWriter)
	if err != nil {
		return f, fmt.Errorf("unable to create private key file %q", err)
	}
	pubWriter, err := os.Create(c.String("public"))
	defer Close(pubWriter)
	if err != nil {
		return f, fmt.Errorf("unable to create public key file %q", err)
	}
	f.prvWriter = prvWriter
	f.pubWriter = pubWriter
	return f, nil
}

func getKeyBytes() (*keyBytes, error) {
	k := &keyBytes{}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return k, fmt.Errorf("error in generating private key %q", err)
	}
	if err := private.Validate(); err != nil {
		return k, fmt.Errorf("error in validating private key %q", err)
	}
	public := private.Public()
	pubCont, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return k, fmt.Errorf("unable to marshall public key %q", err)
	}
	k.privateKey = x509.MarshalPKCS1PrivateKey(private)
	k.publicKey = pubCont
	return k, nil
}

func buildFiles(c *cli.Context) (*encodeParams, error) {
	e := &encodeParams{}
	// open files
	files, err := openFiles(c)
	if err != nil {
		return e, fmt.Errorf("unable to create file %q", err)
	}
	// generate and write to files
	keys, err := getKeyBytes()
	if err != nil {
		return e, fmt.Errorf("unable to generate key %q", err)
	}
	prvPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keys.privateKey,
	}
	pubPem := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: keys.publicKey,
	}
	return &encodeParams{
		prvWriter: files.prvWriter,
		pubWriter: files.pubWriter,
		prvPem:    prvPem,
		pubPem:    pubPem,
	}, nil
}

func encodeFiles(e *encodeParams) error {
	if err := pem.Encode(e.prvWriter, e.prvPem); err != nil {
		return fmt.Errorf("unable to write private key %q", err)
	}
	if err := pem.Encode(e.pubWriter, e.pubPem); err != nil {
		return fmt.Errorf("unable to write public key %q", err)
	}
	return nil
}
