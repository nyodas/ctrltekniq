package vault

import (
	vaultCli "github.com/hashicorp/vault/cli"
	"github.com/nyodas/ctrltekniq/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type MyTestSuite struct {
	suite.Suite
	Client          *Config
	Server          *httptest.Server
	LastRequest     *http.Request
	LastRequestBody string
	ResponseFunc    func(http.ResponseWriter, *http.Request)
}

func (s *MyTestSuite) SetupSuite() {
	go func() {
		_ = vaultCli.Run([]string{
			"server",
			"-dev",
			"-dev-root-token-id=36a85f3d-c418-3cde-d1e9-69c6dfea8f2e",
			"-log-level=info",
		})
	}()
	time.Sleep(1 * time.Second)
	testpki := &pki{
		Name: "ctrltekniq_test_pki",
	}
	testRoles := &role{
		Name: "ctrltekniq_test_role",
		Groups: []string{
			"G_ctrltekniq_test_group",
		},
		CertConfig: roleEntry{
			AllowAnyName: true,
			MaxTTL:       "3h",
		},
	}
	s.Client = &Config{
		Address:       "http://127.0.0.1:8200",
		PkiIssueToken: "36a85f3d-c418-3cde-d1e9-69c6dfea8f2e",
		Pki:           *testpki,
		Roles: []role{
			*testRoles,
		},
	}
	s.Server = httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := ioutil.ReadAll(r.Body)
			s.LastRequestBody = string(body)
			s.LastRequest = r
			if s.ResponseFunc != nil {
				s.ResponseFunc(w, r)
			}
		}))
}

func (s *MyTestSuite) TearDownSuite() {
	s.Server.Close()
}

func (s *MyTestSuite) SetupTest() {
	s.ResponseFunc = nil
	s.LastRequest = nil
}

func TestMySuite(t *testing.T) {
	suite.Run(t, new(MyTestSuite))
}

func (s *MyTestSuite) TestInit() {
	err := s.Client.Init()
	//verify
	assert.NoError(s.T(), err, "noError")
}

func (s *MyTestSuite) TestPing() {
	err := s.Client.Ping()
	//verify
	assert.NoError(s.T(), err, "noError")
}

func (s *MyTestSuite) TestSaveCertSerial() {
	err := s.Client.SaveCertSerial("aa:bb", "test.ctrltekniq")
	//verify
	assert.NoError(s.T(), err, "noError")
}

func (s *MyTestSuite) TestGetTLSConfig() {
	testUser := user.Client{
		Name:   "test.ctrltekniq",
		Groups: "G_ctrltekniq_test_group",
		Mail:   "test.ctrltekniq@ctrltekniq.wtf",
	}
	s.Client.Init()
	certs, err := s.Client.GetTLSConfig(testUser)
	//verify
	assert.NoError(s.T(), err, "noError")
	assert.NotEmpty(s.T(), certs, "noError")
}
