// Recipe persistence for the browser rotation engine. A "recipe" is exactly a Site
// (host + change-password Form + optional verify Login + Proof). Recipes carry NO
// secrets — only selectors and URLs — so unlike vault material they are safe to write
// to an ordinary on-disk JSON file (BROWSERROT-PLAN §4: "store selectors, never values").
//
// This is the "learn once, replay forever" store: Tier-2 healing rewrites a Site's
// selectors in memory (Rotator.Healed / HealedSite); Save persists the rewritten recipe
// so the NEXT run loads it and stays Tier-1 (no LLM). It is the browser analog of the
// rotate driver's ref-map.
package browserrot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// RecipeBook is a host-keyed collection of Site recipes persisted as JSON.
type RecipeBook struct {
	Sites map[string]Site `json:"sites"`
}

// LoadRecipes reads a recipe book from path. A missing file yields an empty book (the
// first run has nothing learned yet), which is not an error.
func LoadRecipes(path string) (*RecipeBook, error) {
	rb := &RecipeBook{Sites: map[string]Site{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return rb, nil
		}
		return nil, fmt.Errorf("browserrot: read recipes %s: %w", path, err)
	}
	if len(data) == 0 {
		return rb, nil
	}
	if err := json.Unmarshal(data, rb); err != nil {
		return nil, fmt.Errorf("browserrot: parse recipes %s: %w", path, err)
	}
	if rb.Sites == nil {
		rb.Sites = map[string]Site{}
	}
	return rb, nil
}

// Get returns the recipe for host and whether one was found.
func (rb *RecipeBook) Get(host string) (Site, bool) {
	s, ok := rb.Sites[host]
	return s, ok
}

// Put stores/overwrites the recipe for its host (Site.Host is the key).
func (rb *RecipeBook) Put(s Site) {
	if rb.Sites == nil {
		rb.Sites = map[string]Site{}
	}
	rb.Sites[s.Host] = s
}

// Save writes the recipe book to path atomically (temp file + rename), 0600 since a
// selector table is not sensitive but is user-owned config. Keys are sorted for a stable
// on-disk diff.
func (rb *RecipeBook) Save(path string) error {
	// Marshal with sorted keys for deterministic output (encoding/json already sorts map
	// keys, but we guard explicitly in case the shape changes).
	ordered := struct {
		Sites map[string]Site `json:"sites"`
	}{Sites: map[string]Site{}}
	hosts := make([]string, 0, len(rb.Sites))
	for h := range rb.Sites {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		ordered.Sites[h] = rb.Sites[h]
	}
	data, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		return fmt.Errorf("browserrot: encode recipes: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("browserrot: mkdir %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("browserrot: write recipes tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("browserrot: commit recipes: %w", err)
	}
	return nil
}
