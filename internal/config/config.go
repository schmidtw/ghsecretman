// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// YAML section and visibility keys recognized by the decoder.
const (
	keyManaged    = "managed"
	keyVars       = "vars"
	keySecrets    = "secrets"
	keyDependabot = "dependabot"
	keyRepos      = "repos"
	visSelected   = "selected"
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
	// OrgScope, when set, holds values written at the GitHub organization
	// level (separate object class from repo-level secrets/variables).
	OrgScope *OrgScope
	// AllRepos, when set, holds values to fan out to every repo in the org.
	// Per-repo entries override or shield individual repos.
	AllRepos *Repo
	PerRepo  map[string]*Repo
}

// OrgScope holds the org-level managed/ignored blocks.
type OrgScope struct {
	Managed OrgManaged
	Ignored Ignored
}

// OrgManaged lists org-level values the tool owns and may write.
type OrgManaged struct {
	Vars       map[string]*OrgEntry
	Secrets    map[string]*OrgEntry
	Dependabot map[string]*OrgEntry
}

// OrgEntry describes one org-managed value with its visibility envelope.
type OrgEntry struct {
	Entry *Entry
	// Visibility is one of "all", "private", "selected". Default: "all".
	Visibility string
	// Repos is the static list of repo names that may access the entry when
	// Visibility == "selected". Required iff Visibility == "selected".
	Repos []string
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
	Name    string
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
				repo, err := decodeRepo(baseDir, repoName, val.Content[j+1])
				if err != nil {
					return nil, err
				}
				org.PerRepo[repoName] = repo
			}
		case "all-repos":
			repo, err := decodeRepo(baseDir, "all-repos", val)
			if err != nil {
				return nil, err
			}
			org.AllRepos = repo
		case "org":
			s, err := decodeOrgScope(baseDir, orgName, val)
			if err != nil {
				return nil, err
			}
			org.OrgScope = s
		default:
			return nil, fmt.Errorf("org %q: unknown key %q", orgName, key)
		}
	}
	return org, nil
}

func decodeOrgScope(baseDir, orgName string, n *yaml.Node) (*OrgScope, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("org %q: org must be a mapping", orgName)
	}
	s := &OrgScope{}
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i].Value
		val := n.Content[i+1]
		switch key {
		case keyManaged:
			m, err := decodeOrgManaged(baseDir, orgName, val)
			if err != nil {
				return nil, err
			}
			s.Managed = m
		case "ignored":
			ig, err := decodeIgnored(fmt.Sprintf("org %q", orgName), val)
			if err != nil {
				return nil, err
			}
			s.Ignored = ig
		default:
			return nil, fmt.Errorf("org %q: org: unknown key %q", orgName, key)
		}
	}
	if err := checkOrgManagedIgnoredConflict(orgName, s); err != nil {
		return nil, err
	}
	return s, nil
}

func checkOrgManagedIgnoredConflict(orgName string, s *OrgScope) error {
	conflicts := []struct {
		section string
		managed map[string]*OrgEntry
		ignored []string
	}{
		{keyVars, s.Managed.Vars, s.Ignored.Vars},
		{keySecrets, s.Managed.Secrets, s.Ignored.Secrets},
		{keyDependabot, s.Managed.Dependabot, s.Ignored.Dependabot},
	}
	for _, c := range conflicts {
		for _, name := range c.ignored {
			if _, ok := c.managed[name]; ok {
				return fmt.Errorf("org %q: %q appears in both org.managed.%s and org.ignored.%s",
					orgName, name, c.section, c.section)
			}
		}
	}
	return nil
}

// decodeOrgManaged parses the org-level managed block.
//
//nolint:dupl // structurally similar to decodeManaged but produces OrgManaged (whose entries carry visibility/repos) rather than Managed.
func decodeOrgManaged(baseDir, orgName string, n *yaml.Node) (OrgManaged, error) {
	var m OrgManaged
	if n.Kind != yaml.MappingNode {
		return m, fmt.Errorf("org %q: org.managed must be a mapping", orgName)
	}
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i].Value
		val := n.Content[i+1]
		switch key {
		case keyVars:
			es, err := decodeOrgEntries(baseDir, orgName, keyVars, val)
			if err != nil {
				return m, err
			}
			m.Vars = es
		case keySecrets:
			es, err := decodeOrgEntries(baseDir, orgName, keySecrets, val)
			if err != nil {
				return m, err
			}
			m.Secrets = es
		case keyDependabot:
			es, err := decodeOrgEntries(baseDir, orgName, keyDependabot, val)
			if err != nil {
				return m, err
			}
			m.Dependabot = es
		default:
			return m, fmt.Errorf("org %q: org.managed: unknown key %q", orgName, key)
		}
	}
	return m, nil
}

func decodeOrgEntries(baseDir, orgName, section string, n *yaml.Node) (map[string]*OrgEntry, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("org %q: org.managed.%s must be a mapping", orgName, section)
	}
	out := map[string]*OrgEntry{}
	for i := 0; i < len(n.Content); i += 2 {
		name := n.Content[i].Value
		val := n.Content[i+1]
		if val.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("org %q: org.managed.%s.%s must use object form (got scalar)", orgName, section, name)
		}
		oe, err := decodeOrgEntry(baseDir, orgName, section, name, val)
		if err != nil {
			return nil, err
		}
		out[name] = oe
	}
	return out, nil
}

func decodeOrgEntry(baseDir, orgName, section, name string, n *yaml.Node) (*OrgEntry, error) {
	e := &Entry{Name: name}
	oe := &OrgEntry{Entry: e}
	hasScope := false
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
		case "scope":
			hasScope = true
			oe.Visibility = v.Value
		case keyRepos:
			list, err := decodeStringList(fmt.Sprintf("org %q", orgName), "org.managed."+section+"."+name+".repos", v)
			if err != nil {
				return nil, err
			}
			oe.Repos = list
		default:
			return nil, fmt.Errorf("org %q: org.managed.%s.%s: unknown key %q", orgName, section, name, k)
		}
	}
	if err := validateEntrySources(fmt.Sprintf("org %q", orgName), "org.managed."+section, name, e); err != nil {
		return nil, err
	}
	if !hasScope {
		oe.Visibility = "all"
	}
	if err := validateOrgVisibility(orgName, section, name, oe); err != nil {
		return nil, err
	}
	return oe, nil
}

func validateOrgVisibility(orgName, section, name string, oe *OrgEntry) error {
	switch oe.Visibility {
	case "all", "private":
		if len(oe.Repos) > 0 {
			return fmt.Errorf("org %q: org.managed.%s.%s: repos may only be set when scope is %q",
				orgName, section, name, visSelected)
		}
	case visSelected:
		if len(oe.Repos) == 0 {
			return fmt.Errorf("org %q: org.managed.%s.%s: scope %q requires a non-empty repos list",
				orgName, section, name, visSelected)
		}
	default:
		return fmt.Errorf("org %q: org.managed.%s.%s: scope must be one of all|private|selected (got %q)",
			orgName, section, name, oe.Visibility)
	}
	return nil
}

func decodeRepo(baseDir, repoName string, n *yaml.Node) (*Repo, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("repo %q must be a mapping", repoName)
	}
	repo := &Repo{}
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i].Value
		val := n.Content[i+1]
		switch key {
		case keyManaged:
			m, err := decodeManaged(baseDir, repoName, val)
			if err != nil {
				return nil, err
			}
			repo.Managed = m
		case "ignored":
			ig, err := decodeIgnored(fmt.Sprintf("repo %q", repoName), val)
			if err != nil {
				return nil, err
			}
			repo.Ignored = ig
		default:
			return nil, fmt.Errorf("repo %q: unknown key %q", repoName, key)
		}
	}
	if err := checkManagedIgnoredConflict(repoName, repo); err != nil {
		return nil, err
	}
	return repo, nil
}

func checkManagedIgnoredConflict(repoName string, r *Repo) error {
	conflicts := []struct {
		section string
		managed map[string]*Entry
		ignored []string
	}{
		{keyVars, r.Managed.Vars, r.Ignored.Vars},
		{keySecrets, r.Managed.Secrets, r.Ignored.Secrets},
		{keyDependabot, r.Managed.Dependabot, r.Ignored.Dependabot},
	}
	for _, c := range conflicts {
		for _, name := range c.ignored {
			if _, ok := c.managed[name]; ok {
				return fmt.Errorf("repo %q: %q appears in both managed.%s and ignored.%s",
					repoName, name, c.section, c.section)
			}
		}
	}
	return nil
}

// decodeManaged parses the repo-level managed block.
//
//nolint:dupl // structurally similar to decodeOrgManaged but produces a different type (Managed vs OrgManaged). Refactoring across types adds more indirection than it removes; the two are short and easy to read in place.
func decodeManaged(baseDir, repoName string, n *yaml.Node) (Managed, error) {
	var m Managed
	if n.Kind != yaml.MappingNode {
		return m, fmt.Errorf("repo %q: managed must be a mapping", repoName)
	}
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i].Value
		val := n.Content[i+1]
		switch key {
		case keyVars:
			entries, err := decodeEntries(baseDir, repoName, keyVars, val)
			if err != nil {
				return m, err
			}
			m.Vars = entries
		case keySecrets:
			entries, err := decodeEntries(baseDir, repoName, keySecrets, val)
			if err != nil {
				return m, err
			}
			m.Secrets = entries
		case keyDependabot:
			entries, err := decodeEntries(baseDir, repoName, keyDependabot, val)
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

func decodeEntries(baseDir, repoName, section string, n *yaml.Node) (map[string]*Entry, error) {
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
	e := &Entry{Name: name}
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
	if err := validateEntrySources(fmt.Sprintf("repo %q", repoName), "managed."+section, name, e); err != nil {
		return nil, err
	}
	return e, nil
}

func validateEntrySources(ctx, section, name string, e *Entry) error {
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
		return fmt.Errorf("%s: %s.%s: must set exactly one of value, env, file (got %d)",
			ctx, section, name, count)
	}
	return nil
}

func decodeIgnored(ctx string, n *yaml.Node) (Ignored, error) {
	var ig Ignored
	if n.Kind != yaml.MappingNode {
		return ig, fmt.Errorf("%s: ignored must be a mapping", ctx)
	}
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i].Value
		val := n.Content[i+1]
		list, err := decodeStringList(ctx, "ignored."+key, val)
		if err != nil {
			return ig, err
		}
		switch key {
		case keyVars:
			ig.Vars = list
		case keySecrets:
			ig.Secrets = list
		case keyDependabot:
			ig.Dependabot = list
		default:
			return ig, fmt.Errorf("%s: ignored: unknown key %q", ctx, key)
		}
	}
	return ig, nil
}

func decodeStringList(ctx, what string, n *yaml.Node) ([]string, error) {
	if n.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s: %s must be a list of strings", ctx, what)
	}
	out := make([]string, 0, len(n.Content))
	for _, item := range n.Content {
		if item.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("%s: %s must be a list of strings", ctx, what)
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
