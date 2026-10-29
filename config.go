package main

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"privacyfilter/filter"

	"gopkg.in/yaml.v3"
)

const privacyFilterProvider = "privacyfilter"
const pluginName = "privacyfilter"

type privacyFilterConfig struct {
	GitleaksTOML      string            `yaml:"gitleaks_toml"`
	SkipModels        []string          `yaml:"skip_models"`
	SkipFormats       []string          `yaml:"skip_formats"`
	SkipPIITypes      []string          `yaml:"skip_pii_types"`
	LogEntities       bool              `yaml:"log_entities"`
	Replacement       string            `yaml:"replacement"`
	ReplacementLabels map[string]string `yaml:"replacement_labels"`
}

// replacementLabel prevents YAML's string decoder from coercing booleans and
// numbers into labels. A null field is left unset by the YAML decoder.
type replacementLabel string

func (label *replacementLabel) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("replacement label must be a string")
	}
	if strings.TrimSpace(node.Value) == "" {
		return fmt.Errorf("replacement label must not be empty or whitespace-only")
	}
	*label = replacementLabel(node.Value)
	return nil
}

type replacementLabels map[string]string

func (labels *replacementLabels) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("replacement_labels must be a mapping")
	}
	if len(node.Content) == 0 {
		return nil
	}
	values := make(map[string]string, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("replacement_labels keys must be strings")
		}
		if key.Value == "" || strings.TrimSpace(key.Value) != key.Value {
			return fmt.Errorf("replacement_labels key %q must be nonempty without edge whitespace", key.Value)
		}
		if _, exists := values[key.Value]; exists {
			return fmt.Errorf("duplicate replacement_labels key %q", key.Value)
		}
		var label replacementLabel
		if err := label.UnmarshalYAML(value); err != nil {
			return fmt.Errorf("replacement_labels[%q]: %w", key.Value, err)
		}
		values[key.Value] = string(label)
	}
	*labels = values
	return nil
}

func (cfg *privacyFilterConfig) UnmarshalYAML(node *yaml.Node) error {
	var values struct {
		GitleaksTOML      string            `yaml:"gitleaks_toml"`
		SkipModels        []string          `yaml:"skip_models"`
		SkipFormats       []string          `yaml:"skip_formats"`
		SkipPIITypes      []string          `yaml:"skip_pii_types"`
		LogEntities       bool              `yaml:"log_entities"`
		Replacement       replacementLabel  `yaml:"replacement"`
		ReplacementLabels replacementLabels `yaml:"replacement_labels"`
	}
	if err := node.Decode(&values); err != nil {
		return err
	}
	*cfg = privacyFilterConfig{
		GitleaksTOML:      values.GitleaksTOML,
		SkipModels:        values.SkipModels,
		SkipFormats:       values.SkipFormats,
		SkipPIITypes:      values.SkipPIITypes,
		LogEntities:       values.LogEntities,
		Replacement:       string(values.Replacement),
		ReplacementLabels: map[string]string(values.ReplacementLabels),
	}
	return nil
}

func defaultConfig() privacyFilterConfig {
	return privacyFilterConfig{}
}

func parseConfig(raw []byte) (privacyFilterConfig, error) {
	cfg := defaultConfig()
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("invalid privacyfilter config: %w", err)
		}
	}
	return cfg, nil
}

// resolveGitleaksPath resolves the configured gitleaks rule file. The return is
// split into a path (may be empty) and an embedded flag: when the path is empty
// and embedded is true, the caller should load the rules baked into the binary.
func (cfg *privacyFilterConfig) resolveGitleaksPath(pluginDir string) (path string, embedded bool) {
	if cfg.GitleaksTOML == "" {
		builtin := filepath.Join(pluginDir, "rules", "gitleaks.toml")
		if _, err := os.Stat(builtin); err == nil {
			return builtin, false
		}
		// No sidecar file: fall back to the rules compiled into the binary.
		return "", true
	}
	if filepath.IsAbs(cfg.GitleaksTOML) {
		return cfg.GitleaksTOML, false
	}
	return filepath.Join(pluginDir, cfg.GitleaksTOML), false
}

func (cfg *privacyFilterConfig) shouldSkip(model, requestedModel, format string) bool {
	for _, m := range cfg.SkipModels {
		pattern := strings.TrimSpace(m)
		if matchModelName(pattern, model) || matchModelName(pattern, requestedModel) {
			return true
		}
	}
	for _, f := range cfg.SkipFormats {
		if strings.EqualFold(strings.TrimSpace(f), format) {
			return true
		}
	}
	return false
}

// matchModelName matches a model name against a skip pattern. `*` is the only
// wildcard (deepseek-*); a pattern without it must match the name exactly,
// case-insensitively. The model name is the upstream model when credential
// selection has already happened, so aliases are matched by their upstream name.
func matchModelName(pattern, name string) bool {
	name = strings.TrimSpace(name)
	if pattern == "" || name == "" {
		return false
	}
	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(pattern, name)
	}
	ok, err := path.Match(strings.ToLower(pattern), strings.ToLower(name))
	return err == nil && ok
}

// invalidSkipModelPatterns returns wildcard patterns that cannot be parsed
// (an unclosed `[`), so typos surface in the log instead of never matching.
func invalidSkipModelPatterns(patterns []string) []string {
	var bad []string
	for _, p := range patterns {
		pattern := strings.TrimSpace(p)
		if pattern == "" || !strings.Contains(pattern, "*") {
			continue
		}
		if _, err := path.Match(pattern, ""); err != nil {
			bad = append(bad, pattern)
		}
	}
	return bad
}

func newFilter(pluginDir string, cfg privacyFilterConfig) (*filter.Filter, error) {
	tomlPath, embedded := cfg.resolveGitleaksPath(pluginDir)

	// The filter loads its rules from a file path. When no sidecar file is
	// present (the common case for store installs), materialize the embedded
	// rules into a temporary file. Compiled rules live in memory, so the temp
	// file is removed right after the filter is constructed.
	if embedded {
		tmp, errTmp := os.CreateTemp("", "privacyfilter-gitleaks-*.toml")
		if errTmp != nil {
			return nil, fmt.Errorf("create temp rules file: %w", errTmp)
		}
		tmpPath := tmp.Name()
		if _, errWrite := tmp.Write(embeddedGitleaks); errWrite != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return nil, fmt.Errorf("write temp rules file: %w", errWrite)
		}
		if errClose := tmp.Close(); errClose != nil {
			os.Remove(tmpPath)
			return nil, fmt.Errorf("close temp rules file: %w", errClose)
		}
		defer func() { _ = os.Remove(tmpPath) }()
		tomlPath = tmpPath
	}

	f, err := filter.New(tomlPath, filter.Config{
		Replacement:       cfg.Replacement,
		ReplacementLabels: cfg.ReplacementLabels,
		DisabledPII:       cfg.SkipPIITypes,
	})
	if err != nil {
		var source string
		switch {
		case embedded:
			source = "embedded rules"
		case cfg.GitleaksTOML != "":
			source = fmt.Sprintf("gitleaks_toml %q", tomlPath)
		default:
			source = fmt.Sprintf("sidecar rules file %q", tomlPath)
		}
		return nil, fmt.Errorf("failed to create privacy filter from %s: %w", source, err)
	}
	rules, skipped := f.Stats()
	pluginLog(context.Background(), logLevelInfo, fmt.Sprintf("privacy filter loaded: %d rules, %d skipped", rules, skipped), map[string]any{
		"rules":         rules,
		"skipped_rules": skipped,
	})
	if unknown := unknownPIITypes(cfg.SkipPIITypes); len(unknown) > 0 {
		pluginLog(context.Background(), logLevelWarn, fmt.Sprintf("privacy filter: unknown skip_pii_types entries ignored: %v (supported: %v)", unknown, filter.PIITypes), map[string]any{
			"unknown_pii_types": unknown,
			"supported":         filter.PIITypes,
		})
	}
	if len(cfg.SkipPIITypes) > 0 {
		pluginLog(context.Background(), logLevelInfo, fmt.Sprintf("privacy filter: disabled PII detectors: %v", cfg.SkipPIITypes), map[string]any{
			"disabled_pii_types": cfg.SkipPIITypes,
		})
	}
	if bad := invalidSkipModelPatterns(cfg.SkipModels); len(bad) > 0 {
		pluginLog(context.Background(), logLevelWarn, fmt.Sprintf("privacy filter: invalid skip_models patterns ignored: %v", bad), map[string]any{
			"invalid_skip_models": bad,
		})
	}
	if len(cfg.SkipModels) > 0 {
		pluginLog(context.Background(), logLevelInfo, fmt.Sprintf("privacy filter: skip_models patterns: %v", cfg.SkipModels), map[string]any{
			"skip_models": cfg.SkipModels,
		})
	}
	return f, nil
}

// unknownPIITypes returns the configured PII type identifiers that the filter
// does not support, so typos surface in the log instead of failing silently.
func unknownPIITypes(types []string) []string {
	var unknown []string
	for _, t := range types {
		if trimmed := strings.TrimSpace(t); trimmed != "" && !filter.IsKnownPIIType(trimmed) {
			unknown = append(unknown, trimmed)
		}
	}
	return unknown
}
