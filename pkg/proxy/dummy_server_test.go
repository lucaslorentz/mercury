package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/schubergphilis/mercury/pkg/healthcheck"
	"github.com/schubergphilis/mercury/pkg/logging"
	"github.com/stretchr/testify/assert"
)

var (
	dummyServer = New("serverid", "servername", 10)
)

func TestDummyRequst(t *testing.T) {
	logging.Configure("stdout", "error")
	h := startHTTPServer()
	startProxyServer(t)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", "http://localhost:12391", nil)
	//req.Header.Set("x-franx-correlation-id", "03fc9fb7-eade-47ef-bbd6-41fbdd11382c")
	req.Header["x-franx-correlation-id"] = []string{"03fc9fb7-eade-47ef-bbd6-41fbdd11382c"}
	log.Printf("Client -> Loadbalancer request: %+v", req)
	res, _ := client.Do(req)
	log.Printf("Client <- Loadbalancer response : %+v", res)

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	assert.Nil(t, err)
	log.Printf("Client <- Loadbalancer Body : %s", body)

	stopProxyServer(t)
	stopHTTPServer(h)

}

func startProxyServer(t *testing.T) {
	dummyServer.SetListener("http", "127.0.0.1", 12391, 1024, &tls.Config{}, 10, 10, 1, "")
	dummyServer.AddBackend("backendid", "backendname", "leastconnected", "http", []string{"localhost"}, 10, ErrorPage{}, ErrorPage{})
	backendNode := NewBackendNode("nodeid", "127.0.0.1", "localhost", 12390, 1024, []string{}, 0, healthcheck.Online)

	backend, err := dummyServer.GetBackend()
	assert.Nil(t, err)
	acl := ACL{Action: "add", HeaderKey: "X-Forwarded-For", HeaderValue: "###CLIENT_IP###"}
	backend.SetACL("in", []ACL{acl})
	backend.AddBackendNode(backendNode)

	log.Printf("proxy starting...")
	go dummyServer.Start()
	log.Printf("proxy started...")
	time.Sleep(2 * time.Second)
}

func stopProxyServer(t *testing.T) {
	log.Printf("proxy stopping...")
	dummyServer.Stop()
	log.Printf("proxy stopped...")
}

func startHTTPServer() *http.Server {
	log.Printf("http starting...")
	addr := ":" + os.Getenv("PORT")
	if addr == ":" {
		addr = ":12390"
	}

	h := &http.Server{Addr: addr, Handler: &server{}}
	logger := log.New(os.Stdout, "", 0)

	go func() {
		logger.Printf("Listening on http://0.0.0.0%s\n", addr)

		if err := h.ListenAndServe(); err != nil {
			logger.Fatal(err)
		}
	}()
	log.Printf("http started...")
	return h
}

type server struct{}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(fmt.Sprintf("Loadbalancer <- HTTPServer ResponseWriter: %+v", r)))
}

func stopHTTPServer(h *http.Server) {
	log.Printf("http stopping...")
	h.Shutdown(context.Background())
	log.Printf("http stopped...")
}
