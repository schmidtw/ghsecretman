// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the parsed ghsecretman configuration.
type Config struct {
	BaseDir string
	Orgs    map[string]*Org
}

// Org returns the named organization config, if present.
func (c *Config) Org(name string) (*Org, bool) {
	o, ok := c.Orgs[name]
	return o, ok
}

// Org holds per-organization configuration.
type Org struct {
	PerRepo map[string]*Repo
}

// Repo holds per-repo configuration.
type Repo struct {
	Managed Managed
	Ignored Ignored
}

// Managed lists values the tool owns and may write.
type Managed struct {
	Vars       map[string]*Entry
	Secrets    map[string]*Entry
	Dependabot map[string]*Entry
}

// Ignored lists names the tool must never touch.
type Ignored struct {
	Vars       []string
	Secrets    []string
	Dependabot []string
}

// Entry describes one managed value.
//
// Exactly one of Value, Env, or File must be set.
type Entry struct {
	Value   string
	Env     string
	File    string
	FileAbs string

	// HasValue distinguishes an explicit empty `value:` from an absent one.
	HasValue bool
}

// Load reads and parses a YAML config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- user-supplied config path is intentional
	if err != nil {
		return nil, err
	}
	return LoadBytes(data, path)
}

// LoadBytes parses YAML bytes. The basePath is the path of the YAML file
// (used to resolve relative `file:` entries to its directory).
func LoadBytes(data []byte, basePath string) (*Config, error) {
	var top yaml.Node
	if err := yaml.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	root := &top
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return &Config{BaseDir: filepath.Dir(basePath), Orgs: map[string]*Org{}}, nil
		}
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("top-level document must be a mapping")
	}

	cfg := &Config{
		BaseDir: filepath.Dir(basePath),
		Orgs:    map[string]*Org{},
	}

	gh := lookupKey(root, "github.com")
	if gh == nil {
		return cfg, nil
	}
	if gh.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("github.com must be a mapping")
	}

	for i := 0; i < len(gh.Content); i += 2 {
		orgName := gh.Content[i].Value
		orgNode := gh.Content[i+1]
		org, err := decodeOrg(cfg.BaseDir, orgName, orgNode)
		if err != nil {
			return nil, err
		}
		cfg.Orgs[orgName] = org
	}
	return cfg, nil
}

func decodeOrg(baseDir, orgName string, n *yaml.Node) (*Org, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("org %q must be a mapping", orgName)
	}
	org := &Org{PerRepo: map[string]*Repo{}}
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i].Value
		val := n.Content[i+1]
		switch key {
		case "per-repo":
			if val.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("org %q: per-repo must be a mapping", orgName)
			}
			for j := 0; j < len(val.Content); j += 2 {
				repoName := val.Content[j].Value
				repo, err := decodeRepo(baseDir, orgName, repoName, val.Content[j+1])
				if err != nil {
					return nil, err
				}
				org.PerRepo[repoName] = repo
			}
		case "org", "all-repos":
			// Out of scope for this slice; reserved for future slices.
			return nil, fmt.Errorf("org %q: scope %q not yet supported", orgName, key)
		default:
			return nil, fmt.Errorf("org %q: unknown key %q", orgName, key)
		}
	}
	return org, nil
}

func decodeRepo(baseDir, orgName, repoName string, n *yaml.Node) (*Repo, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("repo %q must be a mapping", repoName)
	}
	repo := &Repo{}
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i].Value
		val := n.Content[i+1]
		switch key {
		case "managed":
			m, err := decodeManaged(baseDir, orgName, repoName, val)
			if err != nil {
				return nil, err
			}
			repo.Managed = m
		case "ignored":
			ig, err := decodeIgnored(repoName, val)
			if err != nil {
				return nil, err
			}
			repo.Ignored = ig
		default:
			return nil, fmt.Errorf("repo %q: unknown key %q", repoName, key)
		}
	}
	return repo, nil
}

func decodeManaged(baseDir, orgName, repoName string, n *yaml.Node) (Managed, error) {
	var m Managed
	if n.Kind != yaml.MappingNode {
		return m, fmt.Errorf("repo %q: managed must be a mapping", repoName)
	}
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i].Value
		val := n.Content[i+1]
		switch key {
		case "vars":
			entries, err := decodeEntries(baseDir, orgName, repoName, "vars", val)
			if err != nil {
				return m, err
			}
			m.Vars = entries
		case "secrets":
			entries, err := decodeEntries(baseDir, orgName, repoName, "secrets", val)
			if err != nil {
				return m, err
			}
			m.Secrets = entries
		case "dependabot":
			entries, err := decodeEntries(baseDir, orgName, repoName, "dependabot", val)
			if err != nil {
				return m, err
			}
			m.Dependabot = entries
		default:
			return m, fmt.Errorf("repo %q: managed: unknown key %q", repoName, key)
		}
	}
	return m, nil
}

func decodeEntries(baseDir, orgName, repoName, section string, n *yaml.Node) (map[string]*Entry, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("repo %q: managed.%s must be a mapping", repoName, section)
	}
	out := map[string]*Entry{}
	for i := 0; i < len(n.Content); i += 2 {
		name := n.Content[i].Value
		val := n.Content[i+1]
		if val.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("repo %q: managed.%s.%s must use object form (got scalar)", repoName, section, name)
		}
		e, err := decodeEntry(baseDir, repoName, section, name, val)
		if err != nil {
			return nil, err
		}
		out[name] = e
	}
	return out, nil
}

func decodeEntry(baseDir, repoName, section, name string, n *yaml.Node) (*Entry, error) {
	e := &Entry{}
	for i := 0; i < len(n.Content); i += 2 {
		k := n.Content[i].Value
		v := n.Content[i+1]
		switch k {
		case "value":
			e.HasValue = true
			e.Value = v.Value
		case "env":
			e.Env = v.Value
		case "file":
			e.File = v.Value
			if v.Value != "" {
				if filepath.IsAbs(v.Value) {
					e.FileAbs = filepath.Clean(v.Value)
				} else {
					e.FileAbs = filepath.Clean(filepath.Join(baseDir, v.Value))
				}
			}
		default:
			return nil, fmt.Errorf("repo %q: managed.%s.%s: unknown key %q", repoName, section, name, k)
		}
	}
	if err := validateEntrySources(repoName, section, name, e); err != nil {
		return nil, err
	}
	return e, nil
}

func validateEntrySources(repoName, section, name string, e *Entry) error {
	count := 0
	if e.HasValue {
		count++
	}
	if e.Env != "" {
		count++
	}
	if e.File != "" {
		count++
	}
	if count != 1 {
		return fmt.Errorf("repo %q: managed.%s.%s: must set exactly one of value, env, file (got %d)",
			repoName, section, name, count)
	}
	return nil
}

func decodeIgnored(repoName string, n *yaml.Node) (Ignored, error) {
	var ig Ignored
	if n.Kind != yaml.MappingNode {
		return ig, fmt.Errorf("repo %q: ignored must be a mapping", repoName)
	}
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i].Value
		val := n.Content[i+1]
		list, err := decodeStringList(repoName, "ignored."+key, val)
		if err != nil {
			return ig, err
		}
		switch key {
		case "vars":
			ig.Vars = list
		case "secrets":
			ig.Secrets = list
		case "dependabot":
			ig.Dependabot = list
		default:
			return ig, fmt.Errorf("repo %q: ignored: unknown key %q", repoName, key)
		}
	}
	return ig, nil
}

func decodeStringList(repoName, ctx string, n *yaml.Node) ([]string, error) {
	if n.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("repo %q: %s must be a list of strings", repoName, ctx)
	}
	out := make([]string, 0, len(n.Content))
	for _, item := range n.Content {
		if item.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("repo %q: %s must be a list of strings", repoName, ctx)
		}
		out = append(out, item.Value)
	}
	return out, nil
}

func lookupKey(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
