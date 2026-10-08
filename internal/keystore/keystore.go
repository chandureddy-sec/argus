// Package keystore keeps the optional third-party API keys ReconX's passive
// sources can use, so they don't have to be exported in every shell.
//
// Keys live in a small JSON file in the user's config directory
// (%AppData%\reconx\keys.json on Windows, ~/.config/reconx/keys.json on
// Linux), written with owner-only permissions. Environment variables always
// win over the file: Apply copies a stored key into its environment variable
// only when that variable is unset, and the providers keep reading the
// environment exactly as before.
package keystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Key describes one supported API key.
type Key struct {
	Name    string `json:"name"`    // short id used on the CLI and in the file
	Env     string `json:"env"`     // environment variable the provider reads
	Service string `json:"service"` // human-readable service name
	Effect  string `json:"effect"`  // what having the key changes
	GetURL  string `json:"get_url"` // where to create one
}

// Supported lists every key ReconX understands, in display order.
var Supported = []Key{
	{
		Name: "github", Env: "RECONX_GITHUB_TOKEN", Service: "GitHub code search",
		Effect: "Required — without it the GitHub source is skipped. A classic token with no scopes is enough.",
		GetURL: "https://github.com/settings/tokens",
	},
	{
		Name: "urlscan", Env: "RECONX_URLSCAN_API_KEY", Service: "urlscan.io",
		Effect: "Optional — adds per-capture details (technologies, TLS issuer) and a higher search quota.",
		GetURL: "https://urlscan.io/user/profile/",
	},
	{
		Name: "certspotter", Env: "RECONX_CERTSPOTTER_API_KEY", Service: "Cert Spotter (SSLMate)",
		Effect: "Optional — raises the anonymous limit of 10 subdomain queries per hour.",
		GetURL: "https://sslmate.com/account/api_credentials",
	},
}

// Lookup returns the key definition for a name (case-insensitive) or env var.
func Lookup(name string) (Key, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, k := range Supported {
		if k.Name == n || strings.EqualFold(k.Env, name) {
			return k, true
		}
	}
	return Key{}, false
}

// Names lists the supported key names.
func Names() []string {
	out := make([]string, len(Supported))
	for i, k := range Supported {
		out[i] = k.Name
	}
	return out
}

// Store is the on-disk key file.
type Store struct {
	path string
	mu   sync.Mutex
}

// DefaultPath is the key file in the user's config directory, overridable
// with RECONX_KEYS_FILE (used by tests and portable installs).
func DefaultPath() string {
	if p := os.Getenv("RECONX_KEYS_FILE"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "reconx", "keys.json")
}

// Open returns the store at path ("" for DefaultPath). The file is created
// lazily on the first Set.
func Open(path string) *Store {
	if path == "" {
		path = DefaultPath()
	}
	return &Store{path: path}
}

// Path is the file backing the store.
func (s *Store) Path() string { return s.path }

func (s *Store) load() (map[string]string, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if len(strings.TrimSpace(string(data))) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("key file %s is corrupt: %w", s.path, err)
	}
	return m, nil
}

func (s *Store) save(m map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Get returns the stored value for a key name ("" when unset).
func (s *Store) Get(name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return "", err
	}
	return m[name], nil
}

// Set stores a key. An empty value removes it.
func (s *Store) Set(name, value string) error {
	k, ok := Lookup(name)
	if !ok {
		return fmt.Errorf("unknown key %q (supported: %s)", name, strings.Join(Names(), ", "))
	}
	value = strings.TrimSpace(value)
	if strings.ContainsAny(value, " \t\r\n") {
		return fmt.Errorf("the %s key must not contain whitespace", k.Name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return err
	}
	if value == "" {
		delete(m, k.Name)
	} else {
		m[k.Name] = value
	}
	return s.save(m)
}

// Status is the public view of one key: where it comes from and a masked
// hint. It never carries the key itself.
type Status struct {
	Key
	Source string `json:"source"` // env | file | unset
	Hint   string `json:"hint,omitempty"`
	Shadow bool   `json:"shadowed,omitempty"` // a stored key is overridden by the env var
}

// Statuses reports every supported key. Because Apply copies stored keys into
// the environment, a variable that equals the stored value counts as "file".
func (s *Store) Statuses() ([]Status, error) {
	s.mu.Lock()
	m, err := s.load()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	out := make([]Status, 0, len(Supported))
	for _, k := range Supported {
		st := Status{Key: k, Source: "unset"}
		env := strings.TrimSpace(os.Getenv(k.Env))
		stored := m[k.Name]
		switch {
		case env != "" && env != stored:
			st.Source, st.Hint, st.Shadow = "env", Mask(env), stored != ""
		case stored != "":
			st.Source, st.Hint = "file", Mask(stored)
		}
		out = append(out, st)
	}
	return out, nil
}

// Apply exports stored keys into their environment variables, without
// overriding variables the user already set. It returns the names applied.
func (s *Store) Apply() ([]string, error) {
	s.mu.Lock()
	m, err := s.load()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var applied []string
	for _, k := range Supported {
		v := m[k.Name]
		if v == "" || os.Getenv(k.Env) != "" {
			continue
		}
		if err := os.Setenv(k.Env, v); err == nil {
			applied = append(applied, k.Name)
		}
	}
	sort.Strings(applied)
	return applied, nil
}

// SetAndApply stores a key and updates the running process's environment so
// the next scan uses it immediately. Removing a key also unsets the variable
// when the variable held the stored value (an env var the user exported
// themselves is left alone).
func (s *Store) SetAndApply(name, value string) error {
	k, ok := Lookup(name)
	if !ok {
		return fmt.Errorf("unknown key %q", name)
	}
	old, _ := s.Get(k.Name)
	if err := s.Set(k.Name, value); err != nil {
		return err
	}
	cur := os.Getenv(k.Env)
	value = strings.TrimSpace(value)
	switch {
	case value == "" && cur != "" && cur == old:
		return os.Unsetenv(k.Env)
	case value != "" && (cur == "" || cur == old):
		return os.Setenv(k.Env, value)
	}
	return nil
}

// Mask shows only enough of a key to recognise it: its last four characters.
func Mask(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 8 {
		return strings.Repeat("•", len(v))
	}
	return "••••" + v[len(v)-4:]
}
