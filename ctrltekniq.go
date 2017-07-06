package main

import (
	"net/http"
	"os"

	"github.com/gorilla/mux"
	ctrltekniqHttp "github.com/nyodas/ctrltekniq/http"
	vault "github.com/nyodas/ctrltekniq/vault"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func main() {
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}

	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	err = viper.ReadInConfig() // Find and read the config file
	if err != nil {            // Handle errors reading the config file
		log.Panicf("Fatal error config file: %s \n", err)
	}
	var vaultConfig vault.Config
	err = viper.Sub("vault").Unmarshal(&vaultConfig)
	if err != nil {
		log.Panicf("unable to decode into struct, %v", err)
	}
	if err := vaultConfig.Init(); err != nil {
		log.Panicf("Unable to init Vault client, %v", err)
	}

	hz := &ctrltekniqHttp.HealthzConfig{
		Hostname: hostname,
		Vault:    &vaultConfig,
	}

	healthzHandler, err := ctrltekniqHttp.HandlerHealthz(hz)
	if err != nil {
		log.Fatal(err)
	}

	hc := &ctrltekniqHttp.HealthzConfig{
		Hostname: hostname,
		Vault:    &vaultConfig,
	}

	certsHandler, err := ctrltekniqHttp.HandlerCerts(hc)
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()

	r.Handle("/healthz", healthzHandler).Methods("GET")
	r.Handle("/certs", certsHandler).Methods("GET")
	r.Handle("/metrics", promhttp.Handler()).Methods("GET")
	log.Infof("Vaultconfig: %s", vaultConfig.Address)
	// Bind to a port and pass our router in
	log.Fatal(http.ListenAndServe(":8090", r))
}
