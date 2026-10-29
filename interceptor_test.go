package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"privacyfilter/filter"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func newTestPlugin(t *testing.T) *privacyFilterPlugin {
	t.Helper()
	f, err := filter.New("", filter.Config{})
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
	modified, _, err := p.redactPayload(context.Background(), []byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
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
	modified, _, err := p.redactPayload(context.Background(), []byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
	}
	if modified != nil {
		t.Fatalf("expected nil for no-PII body, got: %s", string(modified))
	}
}

func TestRedactRequestBody_MultiPartContent(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"text","text":"my phone is 13800138000"}]}]}`
	modified, _, err := p.redactPayload(context.Background(), []byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
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
	modified, _, err := p.redactPayload(context.Background(), []byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
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
	resp, err := p.interceptRequest(context.Background(), pluginapi.RequestInterceptRequest{
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
	resp, err := p.interceptRequest(context.Background(), pluginapi.RequestInterceptRequest{
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

func TestInterceptRequestBeforeAuth_Passthrough(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"normal text"}]}`
	resp, err := p.interceptRequest(context.Background(), pluginapi.RequestInterceptRequest{
		Body: []byte(body),
	})
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatal("expected no modification for non-PII text")
	}
}

func TestRedactRequestBody_KeywordOverlappingCandidateDoesNotPanic(t *testing.T) {
	p := newTestPlugin(t)
	text := strings.Repeat(".", 26) + "api key" + strings.Repeat("A", 20)
	payload, err := json.Marshal(map[string]any{
		"model":    "gpt-4",
		"messages": []any{map[string]any{"role": "user", "content": text}},
	})
	if err != nil {
		t.Fatal(err)
	}
	modified, _, err := p.redactPayload(context.Background(), payload)
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
	}
	if modified != nil {
		t.Fatalf("low-entropy text should be unchanged, got: %s", modified)
	}
}

func TestRedactRequestBody_SecretDetection(t *testing.T) {
	p := newTestPlugin(t)

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my api key is AKIAIOSFODNN7EXAMPLE"}]}`
	modified, _, err := p.redactPayload(context.Background(), []byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
	}
	if modified == nil {
		t.Fatal("expected AWS key to be redacted")
	}
	if strings.Contains(string(modified), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("AWS key should be redacted")
	}
}

func TestRedactRequestBody_InvalidJSON(t *testing.T) {
	p := newTestPlugin(t)
	body := `not valid json with email test@example.com`
	modified, _, err := p.redactPayload(context.Background(), []byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
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

// Build the public plugin with a minimal rules file so these tests exercise
// configuration and hooks without depending on optional sidecar rules.
func newConfiguredInterceptor(t *testing.T, configYAML string) pluginapi.RequestInterceptor {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.toml"), []byte("title = \"consumer test\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	plugin, err := buildPlugin([]byte("gitleaks_toml: rules.toml\n"+configYAML), dir)
	if err != nil {
		t.Fatalf("buildPlugin() error = %v", err)
	}
	return plugin.Capabilities.RequestInterceptor
}

func assertJSONBody(t *testing.T, body []byte, expected string) {
	t.Helper()
	var got, want any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("invalid response JSON %s: %v", body, err)
	}
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("response = %s, want %s", body, expected)
	}
}

func TestBuildPluginRejectsInvalidReplacementConfig(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"global empty", `replacement: ""`},
		{"global whitespace", `replacement: " \t "`},
		{"global boolean", `replacement: true`},
		{"global integer", `replacement: 123`},
		{"global float", `replacement: 1.25`},
		{"global timestamp", `replacement: 2026-10-07`},
		{"global sequence", `replacement: [hidden]`},
		{"global mapping", `replacement: {label: hidden}`},
		{"labels scalar", `replacement_labels: hidden`},
		{"labels boolean", `replacement_labels: false`},
		{"labels sequence", `replacement_labels: [hidden]`},
		{"label empty", `replacement_labels: {email: ""}`},
		{"label whitespace", `replacement_labels: {email: " \t "}`},
		{"label boolean", `replacement_labels: {email: true}`},
		{"label integer", `replacement_labels: {email: 123}`},
		{"label float", `replacement_labels: {email: 1.25}`},
		{"label timestamp", `replacement_labels: {email: 2026-10-07}`},
		{"label null", `replacement_labels: {email: null}`},
		{"label sequence", `replacement_labels: {email: [hidden]}`},
		{"label mapping", `replacement_labels: {email: {label: hidden}}`},
		{"key empty", `replacement_labels: {"": hidden}`},
		{"key leading whitespace", `replacement_labels: {" email": hidden}`},
		{"key trailing whitespace", `replacement_labels: {"email ": hidden}`},
		{"key tab", `replacement_labels: {"email\t": hidden}`},
		{"key number", `replacement_labels: {123: hidden}`},
		{"key boolean", `replacement_labels: {true: hidden}`},
		{"key null", `replacement_labels: {null: hidden}`},
		{"key sequence", "replacement_labels:\n  ? [email]\n  : hidden"},
		{"duplicate type key", "replacement_labels:\n  email: first\n  email: second"},
		{"duplicate global field", "replacement: first\nreplacement: second"},
		{"duplicate labels field", "replacement_labels: {}\nreplacement_labels: {}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildPlugin([]byte(tc.yaml), t.TempDir()); err == nil {
				t.Fatalf("buildPlugin accepted invalid config: %s", tc.yaml)
			}
		})
	}
}

func TestConfiguredReplacementPriority(t *testing.T) {
	const input = `{"input":"raw [邮箱]; test@example.com; 13800138000"}`
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"defaults", "", `{"input":"raw [邮箱]; [邮箱]; [电话]"}`},
		{"null unset", "replacement: null\nreplacement_labels: null", `{"input":"raw [邮箱]; [邮箱]; [电话]"}`},
		{"empty mapping", "replacement_labels: {}", `{"input":"raw [邮箱]; [邮箱]; [电话]"}`},
		{"global", "replacement: '[REDACTED]'", `{"input":"raw [邮箱]; [REDACTED]; [REDACTED]"}`},
		{"type before global", "replacement: '[REDACTED]'\nreplacement_labels:\n  email: '<MAIL>'", `{"input":"raw [邮箱]; <MAIL>; [REDACTED]"}`},
		{"type before default", "replacement_labels:\n  email: '<MAIL>'", `{"input":"raw [邮箱]; <MAIL>; [电话]"}`},
		{"future type accepted", "replacement_labels:\n  future_entity: '[FUTURE]'", `{"input":"raw [邮箱]; [邮箱]; [电话]"}`},
		{"quoted numeric label", "replacement: '123'", `{"input":"raw [邮箱]; 123; 123"}`},
		{"quoted boolean label", "replacement: 'true'", `{"input":"raw [邮箱]; true; true"}`},
		{"label whitespace preserved", "replacement_labels:\n  email: ' [邮箱] '", `{"input":"raw [邮箱];  [邮箱] ; [电话]"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			interceptor := newConfiguredInterceptor(t, tc.yaml)
			resp, err := interceptor.InterceptRequestAfterAuth(nil, pluginapi.RequestInterceptRequest{Body: []byte(input)})
			if err != nil {
				t.Fatal(err)
			}
			assertJSONBody(t, resp.Body, tc.want)
		})
	}
}

func TestConfiguredReplacementRequestStructures(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "replacement: '[REDACTED]'\nreplacement_labels:\n  email: '[邮箱]'")
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"messages string content",
			`{"model":"gpt-4","messages":[{"role":"system","content":"raw [邮箱]"},{"role":"user","content":"test@example.com / 13800138000"}],"temperature":0.5}`,
			`{"model":"gpt-4","messages":[{"role":"system","content":"raw [邮箱]"},{"role":"user","content":"[邮箱] / [REDACTED]"}],"temperature":0.5}`,
		},
		{
			"messages multipart content",
			`{"messages":[{"role":"user","content":[{"type":"text","text":"test@example.com"},{"type":"image_url","image_url":{"url":"https://example.com/test@example.com"}},{"type":"text","text":42}]}]}`,
			`{"messages":[{"role":"user","content":[{"type":"text","text":"[邮箱]"},{"type":"image_url","image_url":{"url":"https://example.com/test@example.com"}},{"type":"text","text":42}]}]}`,
		},
		{
			"input string",
			`{"input":"raw [邮箱] test@example.com 13800138000","metadata":{"email":"test@example.com"}}`,
			`{"input":"raw [邮箱] [邮箱] [REDACTED]","metadata":{"email":"test@example.com"}}`,
		},
		{
			"input string content",
			`{"input":[{"role":"user","content":"test@example.com"},{"type":"function_call","arguments":"test@example.com"}]}`,
			`{"input":[{"role":"user","content":"[邮箱]"},{"type":"function_call","arguments":"test@example.com"}]}`,
		},
		{
			"input multipart content",
			`{"input":[{"role":"user","content":[{"type":"input_text","text":"test@example.com"},{"type":"input_image","image_url":"https://example.com/test@example.com"},{"type":"input_file","file_data":"test@example.com"}]}]}`,
			`{"input":[{"role":"user","content":[{"type":"input_text","text":"[邮箱]"},{"type":"input_image","image_url":"https://example.com/test@example.com"},{"type":"input_file","file_data":"test@example.com"}]}]}`,
		},
		{
			"messages and input both redacted",
			`{"messages":[{"content":"test@example.com"}],"input":"test@example.com"}`,
			`{"messages":[{"content":"[邮箱]"}],"input":"[邮箱]"}`,
		},
		{
			"input redacted when messages has no hit",
			`{"messages":[{"content":"normal text"}],"input":"test@example.com"}`,
			`{"messages":[{"content":"normal text"}],"input":"[邮箱]"}`,
		},
		{
			"input redacted when messages is null",
			`{"messages":null,"input":"test@example.com"}`,
			`{"messages":null,"input":"[邮箱]"}`,
		},
		{
			"mixed content and nonobjects",
			`{"messages":[null,7,"test@example.com",{"content":42},{"content":{"text":"test@example.com"}},{"content":[null,7,{"text":false},{"text":"test@example.com"}]}]}`,
			`{"messages":[null,7,"test@example.com",{"content":42},{"content":{"text":"test@example.com"}},{"content":[null,7,{"text":false},{"text":"[邮箱]"}]}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := interceptor.InterceptRequestAfterAuth(nil, pluginapi.RequestInterceptRequest{Body: []byte(tc.body)})
			if err != nil {
				t.Fatal(err)
			}
			assertJSONBody(t, resp.Body, tc.want)
		})
	}
}

func TestConfiguredReplacementPassesNontextAndNoHitsThrough(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "replacement: '[REDACTED]'")
	for _, body := range []string{
		`{"input":"raw [邮箱] ordinary text"}`,
		`{"messages":[{"content":[{"type":"image_url","image_url":{"url":"https://example.com/test@example.com"}}]}]}`,
		`{"input":[{"type":"function_call","arguments":"test@example.com"}]}`,
		`{"messages":[{"content":42},{"content":null},{"content":{"text":"test@example.com"}}]}`,
		`{"messages":42}`,
		`{"input":{"text":"test@example.com"}}`,
		`{"metadata":{"email":"test@example.com"}}`,
		`not JSON test@example.com`,
		"",
	} {
		resp, err := interceptor.InterceptRequestAfterAuth(nil, pluginapi.RequestInterceptRequest{Body: []byte(body)})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Body != nil {
			t.Fatalf("expected passthrough for %s, got %s", body, resp.Body)
		}
	}
}

func TestConfiguredReplacementBothHooksRemainStable(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, `
replacement: '[REDACTED]'
replacement_labels:
  email: '[邮箱]'
  secret: '[密钥]'
  phone: '[电话]'
  id: '[身份证]'
  bank_card: '[银行卡]'
  ip: '[IP]'
`)
	body := []byte(`{"input":"raw [邮箱]; test@example.com; 13800138000; 11010519900307743X; 4111111111111111; 192.168.1.1; AKIAIOSFODNN7EXAMPLE"}`)
	req := pluginapi.RequestInterceptRequest{Body: body}
	before, err := interceptor.InterceptRequestBeforeAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// 本 fork 的 before-auth 是空操作：跳过与否要等选完凭据、知道上游模型后才可知。
	if before.Body != nil {
		t.Fatalf("before-auth must pass through in this fork, got %s", before.Body)
	}
	after, err := interceptor.InterceptRequestAfterAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, after.Body, `{"input":"raw [邮箱]; [邮箱]; [电话]; [身份证]; [银行卡]; [IP]; [密钥]"}`)
	req.Body = after.Body
	second, err := interceptor.InterceptRequestAfterAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if second.Body != nil {
		t.Fatalf("already-redacted labels must pass through, got %s", second.Body)
	}
}

func TestConfiguredReplacementPreservesSkipConfig(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "replacement: '[REDACTED]'\nskip_models: [' GPT-4 ']\nskip_formats: [' OPENAI ']")
	body := []byte(`{"input":"test@example.com"}`)
	for _, req := range []pluginapi.RequestInterceptRequest{
		{Model: "gpt-4", Body: body},
		{RequestedModel: "gpt-4", Body: body},
		{SourceFormat: "openai", Body: body},
	} {
		before, err := interceptor.InterceptRequestBeforeAuth(nil, req)
		if err != nil {
			t.Fatal(err)
		}
		after, err := interceptor.InterceptRequestAfterAuth(nil, req)
		if err != nil {
			t.Fatal(err)
		}
		if before.Body != nil || after.Body != nil {
			t.Fatalf("skip config must preserve request body: before=%s after=%s", before.Body, after.Body)
		}
	}
}

// ---- 本 fork 相对上游的差异化测试 ----

// after-auth 是本 fork 唯一的脱敏点（before-auth 一律放行）。
func TestInterceptRequestAfterAuth_RedactsFinalRequest(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my email is test@example.com"}]}`
	resp, err := p.InterceptRequestAfterAuth(context.Background(), pluginapi.RequestInterceptRequest{
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

// before-auth 一律放行：跳过与否取决于上游模型，而它要等选完凭据才可知。
func TestInterceptRequestBeforeAuth_DoesNotRedact(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"mail test@example.com token aB3xK9pLmN2qR7sT5vW1zY"}]}`
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
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
	resp, err := p.InterceptRequestAfterAuth(context.Background(), pluginapi.RequestInterceptRequest{
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

// 反面：落到别的上游时仍要脱敏。
func TestInterceptRequestAfterAuth_RedactsOtherUpstream(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.SkipModels = []string{"deepseek-*"}
	body := `{"model":"claude-opus-5","messages":[{"role":"user","content":"mail test@example.com"}]}`
	resp, err := p.InterceptRequestAfterAuth(context.Background(), pluginapi.RequestInterceptRequest{
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

// skip_pii_types 必须真的传到过滤库：关掉 email 后地址原样通过，其它检测器照常工作。
func TestNewFilterSkipPIITypesDisablesEmail(t *testing.T) {
	cfg := defaultConfig()
	cfg.SkipPIITypes = []string{"email"}
	f, err := newFilter(t.TempDir(), cfg)
	if err != nil {
		t.Fatalf("newFilter() error = %v", err)
	}
	p := &privacyFilterPlugin{cfg: cfg, filter: f}

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"mail test@example.com phone 13800138000"}]}`
	modified, _, err := p.redactPayload(context.Background(), []byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
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

// log_entities 只增加日志输出：脱敏本身不能改变。
func TestLogEntitiesKeepsRedaction(t *testing.T) {
	cfg := defaultConfig()
	cfg.LogEntities = true
	f, err := newFilter(t.TempDir(), cfg)
	if err != nil {
		t.Fatalf("newFilter() error = %v", err)
	}
	p := &privacyFilterPlugin{cfg: cfg, filter: f}

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"token aB3xK9pLmN2qR7sT5vW1zY and mail test@example.com"}]}`
	modified, _, err := p.redactPayload(context.Background(), []byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
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
	if !strings.Contains(string(modified), "[邮箱]") {
		t.Fatalf("expected [邮箱] placeholder: %s", string(modified))
	}
}
