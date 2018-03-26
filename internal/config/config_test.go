package config

import (
	"testing"

	"github.com/schubergphilis/mercury/pkg/logging"
	"github.com/schubergphilis/mercury/pkg/param"
)

func TestConfig(t *testing.T) {
	t.Logf("TestConfig...")
	logging.Configure("stdout", "error")
	if err := LoadConfig("nonexistantfile"); err == nil {
		t.Errorf("Expected error on loading false config (got:%s)", err)
	}

	if err := LoadConfig("../../test/broken-config.toml"); err == nil {
		t.Errorf("Expected error on loading false config (got:%s)", err)
	}

	if err := LoadConfig("../../test/second-config.toml"); err != nil {
		t.Errorf("Expected error on loading false config (got:%s)", err)
	}

	if Get().DNS.Settings.Addr != "localhost:53" {
		t.Errorf("Expected DNS binding to be test-second-config (got:%s)", Get().DNS.Settings.Addr)
	}

	param.SetConfig("../../test/broken-config.toml")
	ReloadConfig()

	if Get().DNS.Settings.Addr != "localhost:53" {
		t.Errorf("Expected DNS binding to be test-broken-config (got:%s)", Get().DNS.Settings.Addr)
	}

	param.SetConfig("../../test/second-config.toml")
	ReloadConfig()

	Lock()
	config.DNS.Settings.Addr = "test"
	Unlock()

	if Get().DNS.Settings.Addr != "test" {
		t.Errorf("Expected DNS binding to be test (got:%s)", Get().DNS.Settings.Addr)
	}

}
