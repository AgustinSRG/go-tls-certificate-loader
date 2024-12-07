# Utility library to load TLS certificate (Go)

This is an utility library to load TLS certificate chain and private key from files. It will check for changes in the files periodically and update them, allowing you to set up an auto-renewal process without worrying about restarting the server process.

[Documentation](https://pkg.go.dev/github.com/AgustinSRG/go-tls-certificate-loader)

## Installation

To install the library in your project, run:

```sh
go get github.com/AgustinSRG/go-tls-certificate-loader
```

## Usage

To use the library, create a loader calling `NewTlsCertificateLoader`. Then, use its `GetCertificate` function in the TLS configuration of your server.

Here is en example usage

```go
package main

import (
    "fmt"
    "crypto/tls"
    "net/http"
    "time"
    // Import the module
    tls_certificate_loader "github.com/AgustinSRG/go-tls-certificate-loader"
)

func main() {
	// Create the loader
	loader, err := NewTlsCertificateLoader(TlsCertificateLoaderConfig{
		// Path to the certificate and the key
		CertificatePath: "/path/to/certificate.pem",
		KeyPath:         "/path/to/key.pem",

		// Interval to check for changes
		CheckReloadPeriod: 5 * time.Minute,

		// Event functions
		OnReload: func() {
			fmt.Println("Certificate was reloaded!")
		},
		OnError: func(err error) {
			fmt.Printf("Error loading certificate: %v \n", err)
		},
	})

	if err != nil {
		fmt.Printf("Error loading certificate: %v \n", err)
		return
	}

	defer loader.Close() // Stop the loader after the main process is finished

	// Create TLS server

	tlsServer := http.Server{
		Addr: ":443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			fmt.Fprint(w, "Hello world!")
		}),
		TLSConfig: &tls.Config{
			// Provide the GetCertificate function of the loader
			GetCertificate: loader.GetCertificate,
		},
	}

	fmt.Println("Server listening on port 443!")

	// Listen and serve requests

	err = tlsServer.ListenAndServeTLS("", "")

	if err != nil {
		fmt.Printf("Server error: %v \n", err)
	}
}
```

## Build the library

To install dependencies, run:

```sh
go get .
```

To build the code, run:

```sh
go build .
```

## Run linter

To run the code linter, run:

```sh
golangci-lint run
```

## Run tests

In order to run the tests for this library, run:

```sh
go test -v
```
