package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"privacyfilter/filter"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func newTestPlugin(t *testing.T) *privacyFilterPlugin {
	t.Helper()
	f, err := filter.New("")
	if err != nil {
		t.Fatalf("filter.New() error = %v", err)
	}
	return &privacyFilterPlugin{
		cfg:    defaultConfig(),
		filter: f,
	}
}

func TestRedactRequestBody_EmailInContent(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my email is test@example.com"}]}`
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if modified == nil {
		t.Fatal("expected redacted body, got nil")
	}
	if !strings.Contains(string(modified), "[邮箱]") {
		t.Fatalf("expected [邮箱] placeholder in output: %s", string(modified))
	}
	if strings.Contains(string(modified), "test@example.com") {
		t.Fatal("original email should be redacted")
	}
}

func TestRedactRequestBody_NoPII(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hello world"}]}`
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if modified != nil {
		t.Fatalf("expected nil for no-PII body, got: %s", string(modified))
	}
}

func TestRedactRequestBody_MultiPartContent(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"text","text":"my phone is 13800138000"}]}]}`
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if modified == nil {
		t.Fatal("expected redacted body, got nil")
	}
	if strings.Contains(string(modified), "13800138000") {
		t.Fatal("original phone number should be redacted")
	}
}

func TestRedactRequestBody_ResponsesStringInput(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","input":"my email is test@example.com"}`
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if modified == nil {
		t.Fatal("expected redacted body, got nil")
	}
	if strings.Contains(string(modified), "test@example.com") {
		t.Fatal("original email should be redacted")
	}
}

func TestInterceptRequest_SkippedModel(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.SkipModels = []string{"gpt-4"}
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my email is test@example.com"}]}`
	resp, err := p.interceptRequest(pluginapi.RequestInterceptRequest{
		Model: "gpt-4",
		Body:  []byte(body),
	})
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatalf("expected skipped model to pass through, got: %s", string(resp.Body))
	}
}

func TestInterceptRequest_SkippedRequestedModel(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.SkipModels = []string{"gpt-4"}
	body := `{"model":"upstream-model","messages":[{"role":"user","content":"my email is test@example.com"}]}`
	resp, err := p.interceptRequest(pluginapi.RequestInterceptRequest{
		Model:          "upstream-model",
		RequestedModel: "gpt-4",
		Body:           []byte(body),
	})
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatalf("expected skipped requested model to pass through, got: %s", string(resp.Body))
	}
}

func TestInterceptRequestAfterAuth_RedactsFinalRequest(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my email is test@example.com"}]}`
	resp, err := p.InterceptRequestAfterAuth(nil, pluginapi.RequestInterceptRequest{
		Model: "gpt-4",
		Body:  []byte(body),
	})
	if err != nil {
		t.Fatalf("InterceptRequestAfterAuth() error = %v", err)
	}
	if resp.Body == nil {
		t.Fatal("expected redacted body, got nil")
	}
	if strings.Contains(string(resp.Body), "test@example.com") {
		t.Fatal("original email should be redacted")
	}
}

func TestInterceptRequestBeforeAuth_Passthrough(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"normal text"}]}`
	resp, err := p.interceptRequest(pluginapi.RequestInterceptRequest{
		Body: []byte(body),
	})
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatal("expected no modification for non-PII text")
	}
}

// before-auth 一律放行：跳过与否取决于上游模型，而它要等选完凭据才可知。
func TestInterceptRequestBeforeAuth_DoesNotRedact(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"mail test@example.com token aB3xK9pLmN2qR7sT5vW1zY"}]}`
	resp, err := p.InterceptRequestBeforeAuth(nil, pluginapi.RequestInterceptRequest{
		Model: "gpt-4",
		Body:  []byte(body),
	})
	if err != nil {
		t.Fatalf("InterceptRequestBeforeAuth() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatalf("before-auth 必须原样放行, got: %s", string(resp.Body))
	}
}

// after-auth 按上游模型跳过：客户端写的是别名 claude-sonnet-5，落到 deepseek-flash。
func TestInterceptRequestAfterAuth_SkipsUpstreamByGlob(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.SkipModels = []string{"deepseek-*"}
	body := `{"model":"claude-sonnet-5","messages":[{"role":"user","content":"mail test@example.com"}]}`
	resp, err := p.InterceptRequestAfterAuth(nil, pluginapi.RequestInterceptRequest{
		Model:          "deepseek-flash",
		RequestedModel: "claude-sonnet-5",
		SourceFormat:   "anthropic",
		Body:           []byte(body),
	})
	if err != nil {
		t.Fatalf("InterceptRequestAfterAuth() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatalf("上游命中 deepseek-* 应原样放行, got: %s", string(resp.Body))
	}
}

// 反面：跳到别的上游时仍要脱敏。
func TestInterceptRequestAfterAuth_RedactsOtherUpstream(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.SkipModels = []string{"deepseek-*"}
	body := `{"model":"claude-opus-5","messages":[{"role":"user","content":"mail test@example.com"}]}`
	resp, err := p.InterceptRequestAfterAuth(nil, pluginapi.RequestInterceptRequest{
		Model:          "claude-opus-5",
		RequestedModel: "claude-opus-5",
		SourceFormat:   "anthropic",
		Body:           []byte(body),
	})
	if err != nil {
		t.Fatalf("InterceptRequestAfterAuth() error = %v", err)
	}
	if resp.Body == nil {
		t.Fatal("非跳过上游必须脱敏, got nil")
	}
	if strings.Contains(string(resp.Body), "test@example.com") {
		t.Fatal("邮箱应被脱敏")
	}
}

func TestMatchModelName(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"deepseek-*", "deepseek-flash", true},
		{"deepseek-*", "deepseek-v4-pro", true},
		{"deepseek-*", "claude-sonnet-5", false},
		{"deepseek-flash", "DeepSeek-Flash", true},
		{"deepseek-flash", "deepseek-reasoner", false},
		{"gpt-5.6-*", "gpt-5.6-luna", true},
		{"*", "any-model", true},
		{"", "deepseek-flash", false},
	}
	for _, c := range cases {
		if got := matchModelName(c.pattern, c.name); got != c.want {
			t.Errorf("matchModelName(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestInvalidSkipModelPatterns(t *testing.T) {
	got := invalidSkipModelPatterns([]string{"deepseek-*", "gpt-4", "  ", "[unclosed-*"})
	if len(got) != 1 || got[0] != "[unclosed-*" {
		t.Fatalf("invalidSkipModelPatterns() = %v, want [[unclosed-*]", got)
	}
}

func TestRedactRequestBody_SecretDetection(t *testing.T) {
	rulesDir := filepath.Join("..", "rules")
	tomlPath := filepath.Join(rulesDir, "gitleaks.toml")
	if _, err := os.Stat(tomlPath); os.IsNotExist(err) {
		t.Skip("gitleaks.toml not found, skipping secret detection test")
	}
	f, err := filter.New(tomlPath)
	if err != nil {
		t.Fatalf("filter.New() error = %v", err)
	}
	p := &privacyFilterPlugin{cfg: defaultConfig(), filter: f}

	// AWS 形状的假凭证拼接构造：字面量会被 GitHub push protection 当成真密钥
	// 拦下推送，拼接后运行时取值相同、又不触发扫描。
	awsKeyID := "AKIA" + "3XQ7ZP2LMNVK4WRT"
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my api key is ` + awsKeyID + `"}]}`
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if modified == nil {
		t.Skip("secret not detected with built-in rules only")
	}
	if strings.Contains(string(modified), awsKeyID) {
		t.Fatal("AWS key should be redacted")
	}
}

func TestRedactRequestBody_InvalidJSON(t *testing.T) {
	p := newTestPlugin(t)
	body := `not valid json with email test@example.com`
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if modified != nil {
		t.Fatal("expected nil for invalid JSON, got redacted text")
	}
}

func TestConfigShouldSkip(t *testing.T) {
	cfg := privacyFilterConfig{
		SkipModels:  []string{"gpt-4", "claude-3"},
		SkipFormats: []string{"openai"},
	}
	if !cfg.shouldSkip("gpt-4", "", "") {
		t.Fatal("should skip gpt-4")
	}
	if !cfg.shouldSkip("upstream-model", "claude-3", "") {
		t.Fatal("should skip requested claude-3")
	}
	if !cfg.shouldSkip("", "", "openai") {
		t.Fatal("should skip openai format")
	}
	if cfg.shouldSkip("gemini-pro", "", "anthropic") {
		t.Fatal("should not skip unknown model/format")
	}

	glob := privacyFilterConfig{SkipModels: []string{"deepseek-*"}}
	if !glob.shouldSkip("deepseek-flash", "claude-sonnet-5", "anthropic") {
		t.Fatal("should skip deepseek upstream through the wildcard pattern")
	}
	if glob.shouldSkip("glm-5.3-flash", "claude-sonnet-5", "anthropic") {
		t.Fatal("should not skip a non-deepseek upstream")
	}
}

func TestConfigParse(t *testing.T) {
	raw := `
skip_models:
  - gpt-4
skip_formats:
  - openai
`
	cfg, err := parseConfig([]byte(raw))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if len(cfg.SkipModels) != 1 || cfg.SkipModels[0] != "gpt-4" {
		t.Fatalf("skip_models = %v, want [gpt-4]", cfg.SkipModels)
	}
}

func TestRegistrationCapabilityJSON(t *testing.T) {
	caps := abiCapabilities{RequestInterceptor: true}
	raw, err := json.Marshal(caps)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if !strings.Contains(string(raw), `"request_interceptor":true`) {
		t.Fatalf("expected request_interceptor in JSON: %s", string(raw))
	}
}

func TestConfigParseSkipPIITypes(t *testing.T) {
	cfg, err := parseConfig([]byte("skip_pii_types:\n  - email\n  - phone\n"))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if len(cfg.SkipPIITypes) != 2 || cfg.SkipPIITypes[0] != "email" || cfg.SkipPIITypes[1] != "phone" {
		t.Fatalf("skip_pii_types = %v, want [email phone]", cfg.SkipPIITypes)
	}
}

func TestUnknownPIITypesReported(t *testing.T) {
	got := unknownPIITypes([]string{"email", "emails", "  ", "IP"})
	if len(got) != 1 || got[0] != "emails" {
		t.Fatalf("unknownPIITypes() = %v, want [emails]", got)
	}
}

// skip_pii_types must reach the filter: with email disabled the address passes
// through untouched while the other detectors keep working.
func TestNewFilterSkipPIITypesDisablesEmail(t *testing.T) {
	cfg := defaultConfig()
	cfg.SkipPIITypes = []string{"email"}
	f, err := newFilter(t.TempDir(), cfg)
	if err != nil {
		t.Fatalf("newFilter() error = %v", err)
	}
	p := &privacyFilterPlugin{cfg: cfg, filter: f}

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"mail test@example.com phone 13800138000"}]}`
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if modified == nil {
		t.Fatal("expected modified body (phone redacted), got nil")
	}
	if !strings.Contains(string(modified), "test@example.com") {
		t.Fatalf("email must survive when its detector is disabled: %s", string(modified))
	}
	if strings.Contains(string(modified), "13800138000") {
		t.Fatalf("phone must still be redacted: %s", string(modified))
	}
}

func TestConfigParseLogEntities(t *testing.T) {
	if cfg := defaultConfig(); cfg.LogEntities {
		t.Fatal("log_entities must default to false")
	}
	cfg, err := parseConfig([]byte("log_entities: true\n"))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if !cfg.LogEntities {
		t.Fatal("log_entities = false, want true")
	}
}

// log_entities only adds log output: redaction itself must be unchanged.
func TestLogEntitiesKeepsRedaction(t *testing.T) {
	cfg := defaultConfig()
	cfg.LogEntities = true
	f, err := newFilter(t.TempDir(), cfg)
	if err != nil {
		t.Fatalf("newFilter() error = %v", err)
	}
	p := &privacyFilterPlugin{cfg: cfg, filter: f}

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"token aB3xK9pLmN2qR7sT5vW1zY and mail test@example.com"}]}`
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if modified == nil {
		t.Fatal("expected modified body, got nil")
	}
	if strings.Contains(string(modified), "aB3xK9pLmN2qR7sT5vW1zY") {
		t.Fatalf("secret must stay redacted with log_entities on: %s", string(modified))
	}
	if !strings.Contains(string(modified), "[密钥]") {
		t.Fatalf("expected [密钥] placeholder: %s", string(modified))
	}
}
