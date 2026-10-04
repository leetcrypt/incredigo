package main

import (
	"strings"
	"testing"

	"incredigo/internal/pwstore"
)

func TestParseVerified(t *testing.T) {
	cases := []struct {
		spec    string
		n       int
		want    []int
		wantErr bool
	}{
		{"all", 3, []int{0, 1, 2}, false},
		{"ALL", 2, []int{0, 1}, false},
		{"1,3", 3, []int{0, 2}, false},
		{" 2 , 1 ", 2, []int{1, 0}, false},
		{"0", 3, nil, true}, // 0 is out of the 1-based range
		{"4", 3, nil, true}, // beyond n
		{"x", 3, nil, true}, // non-numeric
		{"", 3, nil, true},  // empty selects nothing
		{",", 3, nil, true}, // no usable entries
	}
	for _, c := range cases {
		got, err := parseVerified(c.spec, c.n)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseVerified(%q,%d) expected error, got %v", c.spec, c.n, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseVerified(%q,%d) unexpected error: %v", c.spec, c.n, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("parseVerified(%q,%d) = %v, want %v", c.spec, c.n, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseVerified(%q,%d) = %v, want %v", c.spec, c.n, got, c.want)
				break
			}
		}
	}
}

func TestRenderPwWorklistSecretsFree(t *testing.T) {
	accts := []pwstore.Account{
		{Site: "github.com", Username: "alice@example.com"},
		{URL: "https://app.example.com/", Username: "bobsecretlogin"},
	}
	md := renderPwWorklist("bitwarden", accts)
	// Numbered, has links, masks usernames, and never contains a full username.
	if !strings.Contains(md, "| 1 |") || !strings.Contains(md, "| 2 |") {
		t.Errorf("worklist not numbered:\n%s", md)
	}
	if !strings.Contains(md, "github.com/settings/tokens") {
		t.Errorf("worklist missing curated github link:\n%s", md)
	}
	if strings.Contains(md, "alice@example.com") || strings.Contains(md, "bobsecretlogin") {
		t.Errorf("worklist leaked a full username:\n%s", md)
	}
}

func TestLinkLabelUnknownHost(t *testing.T) {
	got := linkLabel(pwstore.Account{}) // no site/url
	if !strings.Contains(got, "no rotation page") {
		t.Errorf("linkLabel for empty account = %q", got)
	}
}
