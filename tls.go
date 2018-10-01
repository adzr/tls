/*
Copyright 2018 Ahmed Zaher

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// Config carries the TLS transport configuration.
type Config struct {
	// Cert is the absolute path for the TLS certificate PEM file.
	Cert string `json:"cert,omitempty"`

	// Key is the absolute path for the TLS private key PEM file.
	Key string `json:"key,omitempty"`

	// PassPhrase is the pass-phrase to the private key specified in Key.
	PassPhrase string `json:"passPhrase,omitempty"`
}

func Configuration() *Config {
	return &Config{
		Cert:       "",
		Key:        "",
		PassPhrase: "",
	}
}

func LoadX509Certificates(path string) (certs []*x509.Certificate, err error) {

	certs = make([]*x509.Certificate, 0)

	path = strings.TrimSpace(path)

	err = filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		var PEM []byte

		if PEM, err = ioutil.ReadFile(path); err != nil {
			return err
		}

		for {
			var DERBlock *pem.Block

			DERBlock, PEM = pem.Decode(PEM)

			if DERBlock == nil {
				break
			}

			if DERBlock.Type == "CERTIFICATE" {
				var cert *x509.Certificate

				if cert, err = x509.ParseCertificate(DERBlock.Bytes); err != nil {
					return err
				}

				certs = append(certs, cert)
			}
		}

		return nil
	})

	return
}

func LoadTLSCertificate(conf *Config) (cert *tls.Certificate, err error) {

	certPath, keyPath := strings.TrimSpace(conf.Cert), strings.TrimSpace(conf.Key)

	var (
		keyPEM, certPEM []byte
	)

	if certPEM, err = ioutil.ReadFile(certPath); err != nil {
		return
	}

	if keyPEM, err = ioutil.ReadFile(keyPath); err != nil {
		return
	}

	if keyBlock, _ := pem.Decode(keyPEM); keyBlock == nil {
		err = errors.New("private key file contains no PEM data")
		return
	} else if x509.IsEncryptedPEMBlock(keyBlock) {
		if keyBlock.Bytes, err = x509.DecryptPEMBlock(keyBlock, []byte(conf.PassPhrase)); err != nil {
			return
		}

		keyPEM = pem.EncodeToMemory(keyBlock)
	}

	var c tls.Certificate

	c, err = tls.X509KeyPair(certPEM, keyPEM)

	cert = &c

	return
}
