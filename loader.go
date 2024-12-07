// TLS loader

package tls_certificate_loader

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// TLS certificate loader
type TlsCertificateLoader struct {
	// Configuration
	config TlsCertificateLoaderConfig

	// Mutex for the struct
	mu *sync.Mutex

	// True if the certificate loader is closed
	closed bool

	// Channel to notify the closing of the loader to the co-routine
	closeChan chan struct{}

	// TLS loaded certificate
	certificate *tls.Certificate

	// Last modified time of certificate file
	certModTime time.Time

	// Last modified time of key file
	keyModTime time.Time
}

// Creates a new instance of TlsCertificateLoader
// Also loads the key pair for the first time
//
// # Takes the configuration as the only parameter
//
// Returns an error as the seconds return value if an error occurs loading the key pair for the first time
// In this case, no instance is created, and nil is returned instead as the first return value.
//
// Important: If succeeded, this function starts a new co-routine to periodically reload the key pair.
// If you stop that co-routine, call the Close() function
func NewTlsCertificateLoader(config TlsCertificateLoaderConfig) (*TlsCertificateLoader, error) {
	statCert, err := os.Stat(config.CertificatePath)

	if err != nil {
		return nil, err
	}

	certModTime := statCert.ModTime()

	statKey, err := os.Stat(config.KeyPath)

	keyModTime := statKey.ModTime()

	if err != nil {
		return nil, err
	}

	certificate, err := tls.LoadX509KeyPair(config.CertificatePath, config.KeyPath)

	if err != nil {
		return nil, err
	}

	loader := &TlsCertificateLoader{
		config:      config,
		mu:          &sync.Mutex{},
		closed:      false,
		closeChan:   make(chan struct{}, 1),
		certificate: &certificate,
		certModTime: certModTime,
		keyModTime:  keyModTime,
	}

	go loader.run() // Start co-routine

	return loader, nil
}

// Checks if the loader is closed
// A closed loader is not checking for changes anymore
func (loader *TlsCertificateLoader) IsClosed() bool {
	loader.mu.Lock()
	defer loader.mu.Unlock()

	return loader.closed
}

// Closes the loader, stopping its co-routine
func (loader *TlsCertificateLoader) Close() {
	loader.mu.Lock()

	wasClosed := loader.closed

	loader.closed = true

	loader.mu.Unlock()

	if !wasClosed {
		loader.closeChan <- struct{}{}
	}
}

// Checks for changes in the certificate and key files
// If the certificate and key files have different
// last modified times, they will be reloaded
func (loader *TlsCertificateLoader) check() {
	// Check mod times

	statCert, err := os.Stat(loader.config.CertificatePath)

	if err != nil {
		if loader.config.OnError != nil {
			loader.config.OnError(err)
		}
		return
	}

	certModTime := statCert.ModTime()

	statKey, err := os.Stat(loader.config.KeyPath)

	keyModTime := statKey.ModTime()

	if err != nil {
		if loader.config.OnError != nil {
			loader.config.OnError(err)
		}
		return
	}

	if keyModTime.UnixMilli() == loader.keyModTime.UnixMilli() && certModTime.UnixMilli() == loader.certModTime.UnixMilli() {
		// No changes
		return
	}

	// Reload certificate

	certificate, err := tls.LoadX509KeyPair(loader.config.CertificatePath, loader.config.KeyPath)

	if err != nil {
		if loader.config.OnError != nil {
			loader.config.OnError(err)
		}
		return
	}

	loader.certModTime = certModTime
	loader.keyModTime = keyModTime

	loader.mu.Lock()

	loader.certificate = &certificate

	loader.mu.Unlock()

	if loader.config.OnReload != nil {
		loader.config.OnReload()
	}
}

// Runs the loader co-routine
func (loader *TlsCertificateLoader) run() {
	for {
		select {
		case <-time.After(loader.config.CheckReloadPeriod):
			loader.check()
		case <-loader.closeChan:
			return
		}
	}
}

// Obtains the current loaded TLS key pair
// The client info parameter is ignored
// This function will never return an error
func (loader *TlsCertificateLoader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	loader.mu.Lock()
	defer loader.mu.Unlock()

	return loader.certificate, nil
}
