package vault

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/certutil"
)

type Config struct {
	Address       string
	PkiIssueToken string
	RoleName      string
}

func (vc *Config) Ping() error {
	url := fmt.Sprintf("%s/v1/sys/health", vc.Address)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case 200:
		return nil
	case 429:
		errors.New("unsealed and in standby.")
	case 500:
		errors.New("Sealed or not initialized.")
	}
	return nil
}

func (vc *Config) GetTLSConfig() (string, error) {
	config := &api.Config{
		Address: vc.Address,
	}
	config.ConfigureTLS(&api.TLSConfig{
		Insecure: true,
	})
	client, err := api.NewClient(config)
	if err != nil {
		return "", err
	}
	if client == nil {
		return "", fmt.Errorf("Returned client was nil")
	}

	client.SetToken(vc.PkiIssueToken)
	secret, err := client.Logical().Write(vc.RoleName, map[string]interface{}{
		"common_name": "localhost",
		"ip_sans":     "127.0.0.1",
		"lease":       "1h",
	})
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", fmt.Errorf("Returned secret was nil")
	}

	parsedCertBundle, err := certutil.ParsePKIMap(secret.Data)
	if err != nil {
		return "", fmt.Errorf("Error parsing secret: %s", err)
	}

	certBundle, err := parsedCertBundle.ToCertBundle()
	if err != nil {
		return "", fmt.Errorf("Error bundling cert: %s", err)
	}
	certPem := certBundle.ToPEMBundle()

	/*
		tlsConfig, err := parsedCertBundle.GetTLSConfig(certutil.TLSClient | certutil.TLSServer)
		if err != nil {
			return nil, fmt.Errorf("Could not get TLS config: %s", err)
		}
	*/

	return certPem, nil
}
