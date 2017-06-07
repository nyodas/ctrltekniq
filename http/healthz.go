package http

import (
	"encoding/json"
	"log"
	"net/http"

	vault "github.com/nyodas/ctrltekniq/vault"
)

type HealthzConfig struct {
	Hostname string
	Vault    *vault.Config
}

type healthzHandler struct {
	vc       *vault.Config
	hostname string
	metadata map[string]string
}

func HandlerHealthz(hc *HealthzConfig) (http.Handler, error) {
	metadata := make(map[string]string)
	metadata["vault_address"] = hc.Vault.Address

	h := &healthzHandler{hc.Vault, hc.Hostname, metadata}
	return h, nil
}

type Response struct {
	Hostname string            `json:"hostname"`
	Metadata map[string]string `json:"metadata"`
	Errors   []Error           `json:"errors"`
}

type Error struct {
	Description string            `json:"description"`
	Error       string            `json:"error"`
	Metadata    map[string]string `json:"metadata"`
	Type        string            `json:"type"`
}

func (h *healthzHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	response := Response{
		Hostname: h.hostname,
		Metadata: h.metadata,
	}

	statusCode := http.StatusOK

	errors := make([]Error, 0)

	err := h.vc.Ping()
	if err != nil {
		errors = append(errors, Error{
			Type:        "VaultPing",
			Description: "Vault health check.",
			Error:       err.Error(),
		})
	}

	response.Errors = errors
	if len(response.Errors) > 0 {
		statusCode = http.StatusInternalServerError
		for _, e := range response.Errors {
			log.Println(e.Error)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	data, err := json.MarshalIndent(&response, "", "  ")
	if err != nil {
		log.Println(err)
	}
	w.Write(data)
}
