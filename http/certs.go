package http

import (
	"log"
	"net/http"

	vault "github.com/nyodas/ctrltekniq/vault"
)

type CertsConfig struct {
	Hostname string
	Vault    *vault.Config
}

type certsHandler struct {
	vc *vault.Config
}

func HandlerCerts(hc *HealthzConfig) (http.Handler, error) {
	h := &certsHandler{hc.Vault}
	return h, nil
}

func (h *certsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	response, err := h.vc.GetTLSConfig()

	statusCode := http.StatusOK

	if err != nil {
		statusCode = http.StatusInternalServerError
		log.Println(err)
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(statusCode)
	/*data, err := json.MarshalIndent(&response, "", "  ")
	if err != nil {
		log.Println(err)
	}*/

	w.Write([]byte(response))
}
