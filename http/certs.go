package http

import (
	log "github.com/sirupsen/logrus"

	"net/http"

	"github.com/nyodas/ctrltekniq/user"
	"github.com/nyodas/ctrltekniq/vault"
)

type CertsConfig struct {
	Hostname string
	Vault    *vault.Config
}

type userInfo struct {
	remoteUser string `json:"X-REMOTE-USER" structs:"X-REMOTE-USER" mapstructure:"X-REMOTE-USER"`
}

type certsHandler struct {
	vc *vault.Config
}

func HandlerCerts(hc *HealthzConfig) (http.Handler, error) {
	h := &certsHandler{hc.Vault}
	return h, nil
}

func (h *certsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteUser := r.Header.Get("X-REMOTE-USER")
	remoteMail := r.Header.Get("X-mail")
	remoteAffiliation := r.Header.Get("X-eduPersonAffiliation")

	certsUser := user.Client{
		Name:   remoteUser,
		Groups: remoteAffiliation,
		Mail:   remoteMail,
	}
	statusCode := http.StatusOK

	response, err := h.vc.GetTLSConfig(certsUser)
	if err != nil {
		statusCode = http.StatusInternalServerError
		log.WithError(err).Error("Failed to get Certificate")
	}
	h.vc.SaveCertSerial(response.SerialNumber, certsUser.Name)
	if err != nil {
		log.WithError(err).Error("Failed to save serial")
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("X-REMOTE-USER", remoteUser)
	w.Header().Set("X-mail", remoteMail)
	w.Header().Set("X-eduPersonAffiliation", remoteAffiliation)
	w.WriteHeader(statusCode)
	w.Write([]byte(response.ToPEMBundle()))
}
