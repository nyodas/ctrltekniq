package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	ctrltekniqHttp "github.com/nyodas/ctrltekniq/http"
	vault "github.com/nyodas/ctrltekniq/vault"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"
)

const (
	pkiIssueToken string = "02d470e2-2e47-d97d-8ae9-cc90aec4f2ac"
	vaultAddr     string = "https://172.20.0.39:8200"
	roleName      string = "pki/kubernetes/issue/kubectl"
)

/*

func runServer() {
	tlsConfig, err := getTLSConfig()
	if err != nil {
		log.Printf("[Server] Encountered error getting tls config: %s", err)
		return
	}
	tlsConfig.ServerName = "localhost"
	tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven

	ln, err := net.Listen("tcp", ":9182")
	if err != nil {
		log.Printf("[Server] Error listening: %s", err)
		return
	}
	tlsListener := tls.NewListener(ln.(*net.TCPListener), tlsConfig)

	log.Printf("[Server] Starting...")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch len(r.TLS.VerifiedChains) {
		case 0:
			fmt.Fprintf(w, "Hello! You accesed %q without a client certificate", html.EscapeString(r.URL.Path))
		default:
			fmt.Fprintf(w, "Hello! You accesed %q WITH a client certificate (good job!)", html.EscapeString(r.URL.Path))
		}
	})

	srv := &http.Server{}
	err = srv.Serve(tlsListener)
	if err != nil {
		log.Printf("[Server] Error serving: %s", err)
	}
}

func runClient() {
	tlsConfig, err := getTLSConfig()
	if err != nil {
		log.Printf("[Client] Encountered error getting tls certificate: %s", err)
		return
	}

	log.Printf("[Client] Starting...")

	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}

	for {
		resp, err := client.Get("https://localhost:9182/")
		if err == nil {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Printf("[Client] Error reading response body: %s", err)
			} else {
				log.Printf("[Client] Got %s", string(body))
			}
			resp.Body.Close()
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}
*/
func main() {
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}

	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	err = viper.ReadInConfig() // Find and read the config file
	if err != nil {            // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	var vaultConfig vault.Config
	err = viper.Sub("vault").Unmarshal(&vaultConfig)
	if err != nil {
		panic(fmt.Errorf("unable to decode into struct, %v", err))
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
	log.Printf("Vaultconfig: %s", vaultConfig.Address)
	// runClient()
	// runServer()
	// Bind to a port and pass our router in
	log.Fatal(http.ListenAndServe(":8090", r))
}
