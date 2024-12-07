// Config

package tls_certificate_loader

import "time"

// Configuration for TLS certificate loader
type TlsCertificateLoaderConfig struct {
	// Path to the X.509 certificate chain file
	CertificatePath string

	// Path to the private key file
	KeyPath string

	// Period to check to reload the certificate and key
	CheckReloadPeriod time.Duration

	// Function to call when key pair is reloaded
	OnReload func()

	// Function to call when an error happens reloading the key pair
	OnError func(err error)
}
