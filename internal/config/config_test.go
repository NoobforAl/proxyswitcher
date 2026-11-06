package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxyswitcher.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_EmptyFileUsesSafeDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultListen || cfg.AllowRemote || cfg.DirectFirst || cfg.FallbackDirect {
		t.Fatalf("unsafe defaults: %+v", cfg)
	}
	if len(cfg.BuildSources()) != 0 {
		t.Fatal("no source should be on by default")
	}
}

func TestLoad_ExampleFileIsValid(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "proxyswitcher.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Pool.Cooldown != 30*time.Minute || cfg.HealthCheck.Delay != 500*time.Millisecond {
		t.Fatalf("durations not parsed: %+v", cfg)
	}
	if len(cfg.BuildSources()) != 1 {
		t.Fatalf("sources = %d, want only the personal file", len(cfg.BuildSources()))
	}
}

func TestLoad_MissingFileIsAnError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestLoad_UnknownKeyIsAnError(t *testing.T) {
	if _, err := Load(writeConfig(t, "fallback_directt: true\n")); err == nil {
		t.Fatal("a typo must not be silently ignored")
	}
}

func TestLoad_RefusesOpenProxyUnlessAllowed(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:8899", ":8899", "192.0.2.1:8899"} {
		_, err := Load(writeConfig(t, "listen: \""+listen+"\"\n"))
		if err == nil || !strings.Contains(err.Error(), "allow_remote") {
			t.Errorf("%s: err = %v", listen, err)
		}
		if _, err := Load(writeConfig(t, "allow_remote: true\nlisten: \""+listen+"\"\n")); err != nil {
			t.Errorf("%s with allow_remote: %v", listen, err)
		}
	}
	for _, listen := range []string{"127.0.0.1:1", "localhost:1", "[::1]:1"} {
		if _, err := Load(writeConfig(t, "listen: \""+listen+"\"\n")); err != nil {
			t.Errorf("%s: %v", listen, err)
		}
	}
}

func TestLoad_RejectsBadValues(t *testing.T) {
	for _, content := range []string{
		"listen: nope\n",
		"max_attempts: -1\n",
		"retry_status: [999]\n",
		"pool:\n  evict_max_success_rate: 2\n",
		"pool:\n  cooldown: soon\n",
	} {
		if _, err := Load(writeConfig(t, content)); err == nil {
			t.Errorf("%q: expected an error", content)
		}
	}
}

func TestLoad_EnvOverridesFile(t *testing.T) {
	t.Setenv("PROXYSWITCHER_LISTEN", "127.0.0.1:9000")
	t.Setenv("PROXYSWITCHER_FALLBACK_DIRECT", "true")
	t.Setenv("PROXYSWITCHER_MAX_ATTEMPTS", "9")
	t.Setenv("PROXYSWITCHER_COOLDOWN", "5m")
	t.Setenv("PROXYSWITCHER_DATABAY_ENABLED", "true")
	t.Setenv("DATABAY_API_KEY", "secret-key")

	cfg, err := Load(writeConfig(t, "listen: \"127.0.0.1:1\"\nmax_attempts: 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9000" || !cfg.FallbackDirect || cfg.MaxAttempts != 9 || cfg.Pool.Cooldown != 5*time.Minute {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if cfg.Sources.Databay.APIKey != "secret-key" || len(cfg.BuildSources()) != 1 {
		t.Fatalf("databay not configured: %+v", cfg.Sources.Databay)
	}
}

func TestLoad_BadEnvValueIsAnError(t *testing.T) {
	t.Setenv("PROXYSWITCHER_MAX_ATTEMPTS", "many")
	if _, err := Load(writeConfig(t, "")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestLoad_APIKeyCannotComeFromFile(t *testing.T) {
	t.Setenv("DATABAY_API_KEY", "")
	if _, err := Load(writeConfig(t, "sources:\n  databay:\n    api_key: x\n")); err == nil {
		t.Fatal("api_key in a file should be rejected as an unknown key")
	}
}
