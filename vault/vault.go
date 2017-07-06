package vault

import (
	"crypto/tls"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"

	"encoding/json"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/certutil"
	"github.com/nyodas/ctrltekniq/user"
	"strings"
)

type pki struct {
	Name    string               `json:"name" structs:"name" mapstructure:"name"`
	Options api.MountConfigInput `json:"options" structs:"options" mapstructure:"options"`
	path    string
}

type role struct {
	Name       string    `json:"name" structs:"name" mapstructure:"name"`
	Groups     []string  `json:"groups" structs:"groups" mapstructure:"groups"`
	CertConfig roleEntry `json:"cert_config" structs:"cert_config" mapstructure:"cert_config"`
}

type roleEntry struct {
	LeaseMax              string `json:"lease_max,omitempty" structs:"lease_max" mapstructure:"lease_max"`
	Lease                 string `json:"lease,omitempty" structs:"lease" mapstructure:"lease"`
	MaxTTL                string `json:"max_ttl,omitempty" structs:"max_ttl" mapstructure:"max_ttl"`
	TTL                   string `json:"ttl,omitempty" structs:"ttl" mapstructure:"ttl"`
	AllowLocalhost        bool   `json:"allow_localhost,omitempty" structs:"allow_localhost" mapstructure:"allow_localhost"`
	AllowedBaseDomain     string `json:"allowed_base_domain,omitempty" structs:"allowed_base_domain" mapstructure:"allowed_base_domain"`
	AllowedDomains        string `json:"allowed_domains,omitempty" structs:"allowed_domains" mapstructure:"allowed_domains"`
	AllowBaseDomain       bool   `json:"allow_base_domain,omitempty" structs:"allow_base_domain" mapstructure:"allow_base_domain"`
	AllowBareDomains      bool   `json:"allow_bare_domains,omitempty" structs:"allow_bare_domains" mapstructure:"allow_bare_domains"`
	AllowTokenDisplayName bool   `json:"allow_token_displayname,omitempty" structs:"allow_token_displayname" mapstructure:"allow_token_displayname"`
	AllowSubdomains       bool   `json:"allow_subdomains,omitempty" structs:"allow_subdomains" mapstructure:"allow_subdomains"`
	AllowGlobDomains      bool   `json:"allow_glob_domains,omitempty" structs:"allow_glob_domains" mapstructure:"allow_glob_domains"`
	AllowAnyName          bool   `json:"allow_any_name,omitempty" structs:"allow_any_name" mapstructure:"allow_any_name"`
	EnforceHostnames      bool   `json:"enforce_hostnames,omitempty" structs:"enforce_hostnames" mapstructure:"enforce_hostnames"`
	AllowIPSANs           bool   `json:"allow_ip_sans,omitempty" structs:"allow_ip_sans" mapstructure:"allow_ip_sans"`
	ServerFlag            bool   `json:"server_flag,omitempty" structs:"server_flag" mapstructure:"server_flag"`
	ClientFlag            bool   `json:"client_flag,omitempty" structs:"client_flag" mapstructure:"client_flag"`
	CodeSigningFlag       bool   `json:"code_signing_flag,omitempty" structs:"code_signing_flag" mapstructure:"code_signing_flag"`
	EmailProtectionFlag   bool   `json:"email_protection_flag,omitempty" structs:"email_protection_flag" mapstructure:"email_protection_flag"`
	UseCSRCommonName      bool   `json:"use_csr_common_name,omitempty" structs:"use_csr_common_name" mapstructure:"use_csr_common_name"`
	UseCSRSANs            bool   `json:"use_csr_sans,omitempty" structs:"use_csr_sans" mapstructure:"use_csr_sans"`
	KeyType               string `json:"key_type,omitempty" structs:"key_type" mapstructure:"key_type"`
	KeyBits               int    `json:"key_bits,omitempty" structs:"key_bits" mapstructure:"key_bits"`
	MaxPathLength         *int   `json:",omitempty,omitempty" structs:"max_path_length,omitempty" mapstructure:"max_path_length"`
	KeyUsage              string `json:"key_usage,omitempty" structs:"key_usage" mapstructure:"key_usage"`
	OU                    string `json:"ou,omitempty" structs:"ou" mapstructure:"ou"`
	Organization          string `json:"organization,omitempty" structs:"organization" mapstructure:"organization"`
	GenerateLease         *bool  `json:"generate_lease,omitempty,omitempty" structs:"generate_lease,omitempty"`
	NoStore               bool   `json:"no_store,omitempty" structs:"no_store" mapstructure:"no_store"`
}

type Config struct {
	Address       string `json:"address" structs:"address" mapstructure:"address"`
	PkiIssueToken string `json:"pki_issue_token" structs:"pki_issue_token" mapstructure:"pki_issue_token"`
	Pki           pki    `json:"pki" structs:"pki" mapstructure:"pki"`
	Roles         []role `json:"roles" structs:"roles" mapstructure:"roles"`
	Client        *api.Client
}

func (vc *Config) Init() error {
	log.Info("Initializing Vault Client & PKI")
	config := &api.Config{
		Address: vc.Address,
	}
	config.ConfigureTLS(&api.TLSConfig{
		Insecure: true,
	})
	client, err := api.NewClient(config)
	if err != nil {
		return err
	}
	if client == nil {
		return errors.New("Returned Client was nil")
	}
	vc.Client = client
	vc.Pki.path = "pki/" + vc.Pki.Name
	vc.Client.SetToken(vc.PkiIssueToken)
	if err = vc.pkiInit(); err != nil {
		return err
	}
	if err = vc.rolesInit(); err != nil {
		return err
	}
	return nil
}

func (vc *Config) pkiInit() error {
	rootPkiOptions := map[string]interface{}{
		"common_name": vc.Pki.Name,
		"ttl":         "87600h",
	}
	if err := vc.mount("pki", vc.Pki.path, vc.Pki.Options); err != nil {
		return err
	}
	if _, err := vc.writePost(vc.Pki.path+"/root/generate/internal", rootPkiOptions); err != nil {
		return err
	}

	return nil
}

func (vc *Config) secretsInit() error {
	rootPkiOptions := map[string]interface{}{
		"common_name": vc.Pki.Name,
		"ttl":         "87600h",
	}
	if err := vc.mount("pki", vc.Pki.path, vc.Pki.Options); err != nil {
		return err
	}
	if _, err := vc.writePost(vc.Pki.path+"/root/generate/internal", rootPkiOptions); err != nil {
		return err
	}

	return nil
}

func (vc *Config) mount(mountType string, mountPath string, mountConfig api.MountConfigInput) error {
	mountInfo := &api.MountInput{
		Type:        mountType,
		Description: "",
		Config:      mountConfig,
		Local:       false,
	}

	if err := vc.Client.Sys().Mount(mountPath, mountInfo); err != nil {
		if err != nil && !strings.Contains(err.Error(), "existing mount at") {
			return err
		} else {
			log.Warnf("%s is already mounted", mountPath)
		}
		err = nil
	}
	return nil
}

func (vc *Config) write(writePath string, writeInfo map[string]interface{}) (secret *api.Secret, err error) {
	secret, err = vc.Client.Logical().Write(writePath, writeInfo)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func (vc *Config) writePost(writePath string, writeInfo map[string]interface{}) (secret *api.Secret, err error) {
	secret, err = vc.WritePost(writePath, writeInfo)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func (vc *Config) WritePost(path string, data map[string]interface{}) (*api.Secret, error) {
	r := vc.Client.NewRequest("POST", "/v1/"+path)
	if err := r.SetJSONBody(data); err != nil {
		return nil, err
	}

	resp, err := vc.Client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 200 {
		return api.ParseSecret(resp.Body)
	}

	return nil, nil
}

func (vc *Config) rolesInit() error {
	for _, role := range vc.Roles {
		log.WithField("path", vc.Pki.path).WithField("roles", role.Name).Info("Creating role")
		role.CertConfig.OU = strings.Join(role.Groups, ",")
		certConfig, _ := json.Marshal(role.CertConfig)
		var certConfigMap map[string]interface{}
		_ = json.Unmarshal(certConfig, &certConfigMap)
		if _, err := vc.write(vc.Pki.path+"/roles/"+role.Name, certConfigMap); err != nil {
			return err
		}
	}
	return nil
}

func (vc *Config) matchRole(userRoles string) (role role, err error) {
	for _, role := range vc.Roles {
		isMatch := false
		for _, group := range role.Groups {
			if contains := strings.Contains(userRoles, group); contains != true {
				isMatch = false
				break
			}
			isMatch = true
		}
		if isMatch {
			return role, nil
		}
	}
	return role, errors.New(fmt.Sprintf("Role not found for groups: %v", userRoles))
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

func (vc *Config) SaveCertSerial(serial string, name string) (err error) {
	secret, err := vc.Client.Logical().Read("/secret/" + name)
	if err != nil {
		log.WithError(err).Error("Failed to read Serial List")
	}
	var newSecret map[string]interface{}
	newSecret[serial] = true
	vc.WritePost("/secret/"+name, newSecret)
	log.WithField("serials", secret).Info("Client serials")
	return err
}

func (vc *Config) GetTLSConfig(user user.Client) (certBundle *certutil.CertBundle, err error) {
	role, err := vc.matchRole(user.Groups)
	if err != nil {
		return certBundle, err
	}
	secret, err := vc.Client.Logical().Write(vc.Pki.path+"/issue/"+role.Name, map[string]interface{}{
		"common_name": user.Name,
		"alt_names":   user.Name + "," + user.Mail,
	})
	if err != nil {
		return certBundle, err
	}
	if secret == nil {
		return certBundle, fmt.Errorf("Returned secret was nil")
	}

	parsedCertBundle, err := certutil.ParsePKIMap(secret.Data)
	if err != nil {
		return certBundle, fmt.Errorf("Error parsing secret: %s", err)
	}

	certBundle, err = parsedCertBundle.ToCertBundle()
	if err != nil {
		return certBundle, fmt.Errorf("Error bundling cert: %s", err)
	}
	// certPem := certBundle.ToPEMBundle()

	/*
		tlsConfig, err := parsedCertBundle.GetTLSConfig(certutil.TLSClient | certutil.TLSServer)
		if err != nil {
			return nil, fmt.Errorf("Could not get TLS config: %s", err)
		}
	*/

	return certBundle, nil
}
