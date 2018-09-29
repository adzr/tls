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
	"crypto/x509"
	"os"
	"strings"
	"testing"
)

func compareErrors(e1, e2 error) bool {
	return e1 == e2 || (e1 != nil && e2 != nil && e1.Error() == e2.Error())
}

func getPath(t *testing.T) (path string) {
	path = strings.TrimSuffix(strings.TrimSpace(os.Getenv("GO_TEST_RESOURCE_PATH")), "/")

	if len(path) == 0 {
		t.Errorf("invalid certificate path, please make sure environment variable GO_TEST_RESOURCE_PATH is set correctly")
		t.Fail()
	}

	if f, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("failed to find specified certificate path")
		t.Fail()
	} else if !f.Mode().IsDir() {
		t.Fail()
		t.Errorf("path specified is not a directory")
	}

	return
}

func TestLoadX509Certificates(t *testing.T) {

	path := getPath(t)

	if certs, err := LoadX509Certificates(path); err != nil {
		t.Errorf("error found: %v", err)
	} else if n := len(certs); n != 1 {
		t.Errorf("expected to find 1 certificate, found %v", n)
	} else if name := certs[0].Issuer.CommonName; name != "Test" {
		t.Errorf("expected issuer common name 'Test', found %v", name)
	}
}

func TestGetTLSCertificate(t *testing.T) {

	path := getPath(t)

	inputs := [][]interface{}{
		{"test_rsa", "testing", "test.crt", "Test", nil},
		//{"test_rsa.notfound", "", "test.crt.notfound", "", fmt.Errorf("open %v/test.crt.notfound: no such file or directory", path)},
		//{"test_rsa.bad", "", "test.crt.bad", "", errors.New("certificate file contains no PEM data")},
	}

	for n, input := range inputs {
		var err error

		if e, ok := input[4].(error); ok {
			err = e
		}

		cert, e := LoadTLSCertificate(path+"/"+input[2].(string), path+"/"+input[0].(string), input[1].(string))

		if !compareErrors(e, err) {
			t.Errorf("case %v: expected error: %v, found: %v", n, err, e)
		} else if e == nil && cert == nil {
			t.Errorf("case %v: expected cert, found nil", n)
		} else if e == nil {
			if c, e := x509.ParseCertificate(cert.Certificate[0]); e != nil {
				t.Errorf("case %v: failed to parse certificate", n)
			} else if c.Issuer.CommonName != input[3] {
				t.Errorf("case %v: expected name: %v, found: %v", n, input[3], c.Issuer.CommonName)
			}
		}
	}
}
