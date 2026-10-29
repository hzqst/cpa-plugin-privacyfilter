package main

import (
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var pluginVersion = "0.6.0"

func buildPlugin(configYAML []byte, pluginDir string) (pluginapi.Plugin, error) {
	cfg, errParse := parseConfig(configYAML)
	if errParse != nil {
		return pluginapi.Plugin{}, errParse
	}
	if pluginDir == "" {
		pluginDir = inferPluginDir()
	}

	p := &privacyFilterPlugin{
		cfg:       cfg,
		pluginDir: pluginDir,
	}

	f, errFilter := newFilter(pluginDir, cfg)
	if errFilter != nil {
		return pluginapi.Plugin{}, errFilter
	}
	p.filter = f

	return pluginapi.Plugin{
		Metadata: pluginMetadata(),
		Capabilities: pluginapi.Capabilities{
			RequestInterceptor: p,
		},
	}, nil
}

func pluginMetadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:             pluginName,
		Version:          pluginVersion,
		Author:           "rheodev",
		GitHubRepository: "https://github.com/rheodev/cpa-plugin-privacyfilter",
		ConfigFields: []pluginapi.ConfigField{
			{
				Name:        "gitleaks_toml",
				Type:        pluginapi.ConfigFieldTypeString,
				Description: "Path to gitleaks.toml rules file. Empty uses built-in rules.",
			},
			{
				Name:        "replacement",
				Type:        pluginapi.ConfigFieldTypeString,
				Description: "Global redaction label. Unset uses built-in labels; per-type labels take precedence.",
			},
			{
				Name:        "replacement_labels",
				Type:        pluginapi.ConfigFieldTypeObject,
				Description: "Redaction labels keyed by entity type ID (email, secret, phone, id, bank_card, ip, or future types).",
			},
			{
				Name:        "skip_models",
				Type:        pluginapi.ConfigFieldTypeArray,
				Description: "Upstream model names to skip redaction for; `*` wildcard supported (e.g. deepseek-*).",
			},
			{
				Name:        "skip_formats",
				Type:        pluginapi.ConfigFieldTypeArray,
				Description: "Source format names to skip redaction for.",
			},
			{
				Name:        "skip_pii_types",
				Type:        pluginapi.ConfigFieldTypeArray,
				Description: "Structured PII detectors to disable: email, phone, id_card, ip, bank_card.",
			},
			{
				Name:        "log_entities",
				Type:        pluginapi.ConfigFieldTypeBoolean,
				Description: "Log the original text of every redacted entity (leaks secrets into logs; enable only to debug false positives).",
			},
		},
	}
}
