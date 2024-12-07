// Test

package tls_certificate_loader

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

const test_assets_folder = "./test-assets"
const test_certificate_file = "./test-assets/certificate.pem"
const test_key_file = "./test-assets/key.pem"

func generateAndSaveTestKeyPair(certPath string, keyPath string) {
	// Generate

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tml := x509.Certificate{
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		SerialNumber: big.NewInt(123123),
		Subject: pkix.Name{
			CommonName:   "New Name",
			Organization: []string{"New Org."},
		},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	_ = os.WriteFile(keyPath, []byte(keyPem), 0600)
	_ = os.WriteFile(certPath, []byte(certPem), 0600)
}

func TestTlsCertificateLoader(t *testing.T) {
	// Prepare test assets folder

	_ = os.MkdirAll(test_assets_folder, 0700)

	// Create a test key pair to load

	generateAndSaveTestKeyPair(test_certificate_file, test_key_file)

	// Create loader instance

	var reloaded = false

	loader, err := NewTlsCertificateLoader(TlsCertificateLoaderConfig{
		CertificatePath:   test_certificate_file,
		KeyPath:           test_key_file,
		CheckReloadPeriod: 10 * time.Millisecond,
		OnReload: func() {
			reloaded = true
		},
		OnError: func(err error) {
			t.Error(err)
		},
	})

	if err != nil {
		t.Error(err)
		return
	}

	cert, err := loader.GetCertificate(nil)

	if err != nil {
		t.Error(err)
		return
	}

	if cert == nil {
		t.Errorf("Certificate is nil")
	}

	// Wait

	time.Sleep(1500 * time.Millisecond)

	// Make sure no reloaded

	if reloaded {
		t.Errorf("Key pair was reloaded, but did not change set")
	}

	// Generate new key pair

	generateAndSaveTestKeyPair(test_certificate_file, test_key_file)

	// Wait

	time.Sleep(1500 * time.Millisecond)

	// Make sure it reloaded

	if !reloaded {
		t.Errorf("Key pair was not reloaded after changing")
	}

	newCert, err := loader.GetCertificate(nil)

	if err != nil {
		t.Error(err)
		return
	}

	if newCert == nil {
		t.Errorf("Certificate is nil")
	}

	if newCert == cert {
		t.Errorf("Certificate did not change")
	}

	// Close

	if loader.IsClosed() {
		t.Errorf("Loader is closed, but was not expecting to be closed")
	}

	loader.Close()

	if !loader.IsClosed() {
		t.Errorf("Loader is not closed, but was expecting to be closed")
	}

	// Wait

	time.Sleep(1500 * time.Millisecond)
}

const test_certificate_2_file = "./test-assets/certificate2.pem"
const test_certificate_file_bad = "./test-assets/certificate_bad.pem"
const test_certificate_file_missing = "./test-assets/certificate_missing.pem"

const test_key_2_file = "./test-assets/key2.pem"
const test_key_file_bad = "./test-assets/key_bad.pem"
const test_key_file_missing = "./test-assets/key_missing.pem"

func TestTlsCertificateLoaderErrors(t *testing.T) {
	// Prepare test assets folder

	_ = os.MkdirAll(test_assets_folder, 0700)

	// Create a test key pair to load

	generateAndSaveTestKeyPair(test_certificate_2_file, test_key_2_file)

	// Create set of bad certificate files

	_ = os.WriteFile(test_certificate_file_bad, []byte("This is a bad certificate"), 0600)
	_ = os.WriteFile(test_key_file_bad, []byte("This is a bad key"), 0600)

	// Test error if certificate is missing

	_, err := NewTlsCertificateLoader(TlsCertificateLoaderConfig{
		CertificatePath: test_certificate_file_missing,
		KeyPath:         test_key_file_missing,
	})

	if err == nil {
		t.Errorf("Expected an error, but got none")
	}

	// Test error if key is missing

	_, err = NewTlsCertificateLoader(TlsCertificateLoaderConfig{
		CertificatePath: test_certificate_2_file,
		KeyPath:         test_key_file_missing,
	})

	if err == nil {
		t.Errorf("Expected an error, but got none")
	}

	// Test error if key pair is bad

	_, err = NewTlsCertificateLoader(TlsCertificateLoaderConfig{
		CertificatePath: test_certificate_file_bad,
		KeyPath:         test_key_file_bad,
	})

	if err == nil {
		t.Errorf("Expected an error, but got none")
	}

	// Create loader with good certificates

	var errorCallbackCalled = false
	var reloaded = false

	loader, err := NewTlsCertificateLoader(TlsCertificateLoaderConfig{
		CertificatePath: test_certificate_2_file,
		KeyPath:         test_key_2_file,
		OnError: func(err error) {
			errorCallbackCalled = true
		},
		OnReload: func() {
			reloaded = true
		},
	})

	if err != nil {
		t.Error(err)
		return
	}

	defer loader.Close()

	// Test reload if certificate is missing

	loader.config.CertificatePath = test_certificate_file_missing

	loader.check()

	if !errorCallbackCalled {
		t.Errorf("Error callback was not called")
	}

	if reloaded {
		t.Errorf("Reload callback was called")
	}

	errorCallbackCalled = false
	reloaded = false

	// Test reload if key is missing

	loader.config.CertificatePath = test_certificate_file
	loader.config.KeyPath = test_key_file_missing

	loader.check()

	if !errorCallbackCalled {
		t.Errorf("Error callback was not called")
	}

	if reloaded {
		t.Errorf("Reload callback was called")
	}

	errorCallbackCalled = false
	reloaded = false

	// Test reload if key pair is bad

	time.Sleep(1 * time.Second)

	_ = os.WriteFile(test_certificate_file_bad, []byte("This is a bad certificate (2)"), 0600)
	_ = os.WriteFile(test_key_file_bad, []byte("This is a bad key (2)"), 0600)

	loader.config.CertificatePath = test_certificate_file_bad
	loader.config.KeyPath = test_key_file_bad

	loader.check()

	if !errorCallbackCalled {
		t.Errorf("Error callback was not called")
	}

	if reloaded {
		t.Errorf("Reload callback was called")
	}

	errorCallbackCalled = false
	reloaded = false

	// Test reload if key pair is good

	generateAndSaveTestKeyPair(test_certificate_2_file, test_key_2_file)

	loader.config.CertificatePath = test_certificate_2_file
	loader.config.KeyPath = test_key_2_file

	loader.check()

	if errorCallbackCalled {
		t.Errorf("Error callback was called")
	}

	if !reloaded {
		t.Errorf("Reload callback was not called")
	}

	errorCallbackCalled = false
	reloaded = false
}
