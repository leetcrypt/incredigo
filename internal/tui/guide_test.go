package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"incredigo/internal/discover"
	"incredigo/internal/worklist"
)

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "q":
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func sampleModel() Model {
	items := worklist.Build([]discover.Credential{
		{Source: "git", Identity: "alice @ github.com", Kind: discover.KindToken},
		{Source: "ssh", Identity: "id_ed25519", Kind: discover.KindPrivateKey},
	})
	return New(items)
}

func TestNavigationAndDone(t *testing.T) {
	m := sampleModel()
	if m.cur != 0 {
		t.Fatalf("start cur=%d", m.cur)
	}

	// next
	nm, _ := m.Update(key("n"))
	m = nm.(Model)
	if m.cur != 1 {
		t.Errorf("after n, cur=%d want 1", m.cur)
	}
	// can't go past end
	nm, _ = m.Update(key("n"))
	m = nm.(Model)
	if m.cur != 1 {
		t.Errorf("n past end moved to %d", m.cur)
	}
	// prev
	nm, _ = m.Update(key("p"))
	m = nm.(Model)
	if m.cur != 0 {
		t.Errorf("after p, cur=%d want 0", m.cur)
	}
	// enter marks done and advances
	nm, _ = m.Update(key("enter"))
	m = nm.(Model)
	if !m.done[0] {
		t.Error("enter did not mark item 0 done")
	}
	if m.cur != 1 {
		t.Errorf("enter did not advance, cur=%d", m.cur)
	}
}

func TestQuit(t *testing.T) {
	m := sampleModel()
	nm, cmd := m.Update(key("q"))
	m = nm.(Model)
	if !m.quit {
		t.Error("q did not set quit")
	}
	if cmd == nil {
		t.Error("q should return a quit command")
	}
}

func TestViewContent(t *testing.T) {
	m := sampleModel()
	v := m.View()
	if !strings.Contains(v, "github.com") {
		t.Errorf("view missing identity/link:\n%s", v)
	}
	if !strings.Contains(v, "1 of 2") {
		t.Errorf("view missing progress:\n%s", v)
	}
	if !strings.Contains(v, "no secret") {
		t.Errorf("view missing read-only reassurance:\n%s", v)
	}
}

func TestEmptyModelView(t *testing.T) {
	if got := New(nil).View(); !strings.Contains(got, "No credentials") {
		t.Errorf("empty view = %q", got)
	}
}

func TestInitNoCmd(t *testing.T) {
	if cmd := sampleModel().Init(); cmd != nil {
		t.Errorf("Init returned a command, want nil")
	}
}

// TestUpdateIgnoresNonKeyMsg proves a non-keyboard message leaves the model
// unchanged (the walk-through only responds to key presses).
func TestUpdateIgnoresNonKeyMsg(t *testing.T) {
	m := sampleModel()
	nm, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	if cmd != nil {
		t.Error("non-key msg produced a command")
	}
	if nm.(Model).cur != 0 {
		t.Error("non-key msg moved the cursor")
	}
}

// TestOpenBranches covers "o": on an item with a URL it emits an open command; on an
// item with no rotation page it does nothing.
func TestOpenBranches(t *testing.T) {
	m := sampleModel() // item0 (git) has a URL; item1 (ssh) has none
	_, cmd := m.Update(key("o"))
	if cmd == nil {
		t.Error("o on an item with a URL returned no command")
	}
	nm, _ := m.Update(key("n")) // advance to the URL-less ssh item
	m = nm.(Model)
	if _, cmd := m.Update(key("o")); cmd != nil {
		t.Error("o on an item with no URL returned a command")
	}
}

// TestSkipAndBoundaries covers "s" (skip → next) and the prev/next boundary guards.
func TestSkipAndBoundaries(t *testing.T) {
	m := sampleModel()
	// prev at the first item is a no-op.
	nm, _ := m.Update(key("k"))
	if nm.(Model).cur != 0 {
		t.Error("k at index 0 moved the cursor")
	}
	m = nm.(Model)
	// skip advances.
	nm, _ = m.Update(key("s"))
	m = nm.(Model)
	if m.cur != 1 {
		t.Errorf("s did not advance, cur=%d", m.cur)
	}
	// skip at the last item is a no-op.
	nm, _ = m.Update(key("s"))
	if nm.(Model).cur != 1 {
		t.Error("s past end moved the cursor")
	}
}

// TestEnterAtLastItemStays proves enter marks the last item done without advancing
// past the end of the list.
func TestEnterAtLastItemStays(t *testing.T) {
	m := sampleModel()
	nm, _ := m.Update(key("n")) // to last item (index 1)
	m = nm.(Model)
	nm, _ = m.Update(key("enter"))
	m = nm.(Model)
	if !m.done[1] {
		t.Error("enter did not mark the last item done")
	}
	if m.cur != 1 {
		t.Errorf("enter advanced past the last item, cur=%d", m.cur)
	}
}

// TestQuitVariants covers the esc and ctrl+c quit keys alongside q.
func TestQuitVariants(t *testing.T) {
	for _, k := range []tea.KeyMsg{{Type: tea.KeyEsc}, {Type: tea.KeyCtrlC}} {
		nm, cmd := sampleModel().Update(k)
		if !nm.(Model).quit || cmd == nil {
			t.Errorf("%v did not quit", k)
		}
	}
}

// TestOpenURLCmd invokes the command returned by openURL: it is best-effort (the
// launcher may be absent on a headless host) and must return a nil message.
func TestOpenURLCmd(t *testing.T) {
	if msg := openURL("https://example.com")(); msg != nil {
		t.Errorf("openURL cmd returned %v, want nil", msg)
	}
}

// TestRunEmptyReturnsNil covers Run's headless-safe path: no items → prints a notice
// and returns without launching the (TTY-requiring) Bubble Tea program.
func TestRunEmptyReturnsNil(t *testing.T) {
	if err := Run(nil); err != nil {
		t.Errorf("Run(nil) = %v, want nil", err)
	}
}
