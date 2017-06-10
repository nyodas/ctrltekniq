package http

import (
	"log"
	"net/http"

	"github.com/nyodas/ctrltekniq/user"
	vault "github.com/nyodas/ctrltekniq/vault"
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

	user := user.Client{
		Name:   remoteUser,
		Groups: remoteAffiliation,
		Mail:   remoteMail,
	}
	response, err := h.vc.GetTLSConfig(user)

	statusCode := http.StatusOK

	if err != nil {
		statusCode = http.StatusInternalServerError
		log.Println(err)
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("X-REMOTE-USER", remoteUser)
	w.Header().Set("X-mail", remoteMail)
	w.Header().Set("X-eduPersonAffiliation", remoteAffiliation)
	w.WriteHeader(statusCode)
	/*data, err := json.MarshalIndent(&response, "", "  ")
	if err != nil {
		log.Println(err)
	}*/

	w.Write([]byte(response))
}
