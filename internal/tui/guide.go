// Package tui is the interactive guided-rotation walk-through (Charm Bubble Tea).
//
// It is READ-ONLY guidance: it steps through the rotation worklist one credential
// at a time, generates the change-password link, and can open it — it does NOT
// enter, store, or rotate any secret. Capturing a rotated value (and the backup
// gate that must precede it) is a later, separately-gated step.
package tui

import (
	"fmt"
	"os/exec"
	"runtime"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"incredigo/internal/worklist"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	autoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	manualStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	doneStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	linkStyle   = lipgloss.NewStyle().Underline(true).Foreground(lipgloss.Color("39"))
	keyStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("white")).Background(lipgloss.Color("238")).Padding(0, 1)
)

// Model is the guided-rotation walk-through state. Exported for testing.
type Model struct {
	items []worklist.Item
	cur   int
	done  map[int]bool
	quit  bool
}

// New builds a guide model over a worklist.
func New(items []worklist.Item) Model {
	return Model{items: items, done: map[int]bool{}}
}

func (m Model) Init() tea.Cmd { return nil }

// Update is the Bubble Tea event loop. Exported indirectly via tea; the key
// handling here is what the tests exercise.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "q", "ctrl+c", "esc":
		m.quit = true
		return m, tea.Quit
	case "j", "down", "n", "tab":
		if m.cur < len(m.items)-1 {
			m.cur++
		}
	case "k", "up", "p", "shift+tab":
		if m.cur > 0 {
			m.cur--
		}
	case "o":
		if u := m.items[m.cur].Link.URL; u != "" {
			return m, openURL(u)
		}
	case "enter", " ":
		m.done[m.cur] = true
		if m.cur < len(m.items)-1 {
			m.cur++
		}
	case "s":
		if m.cur < len(m.items)-1 {
			m.cur++
		}
	}
	return m, nil
}

func (m Model) View() string {
	if len(m.items) == 0 {
		return "No credentials to rotate.\n"
	}
	it := m.items[m.cur]

	rot := manualStyle.Render("manual — no API; rotate on the site")
	if !it.Manual() {
		rot = autoStyle.Render("auto: " + it.Driver)
	}
	status := ""
	if m.done[m.cur] {
		status = "  " + doneStyle.Render("✓ done")
	}

	link := dimStyle.Render("— no web page for this credential")
	if it.Link.URL != "" {
		link = linkStyle.Render(it.Link.URL) + dimStyle.Render("  ("+string(it.Link.Source)+")")
	}

	header := titleStyle.Render(fmt.Sprintf("incredigo · guided rotation  —  %d of %d", m.cur+1, len(m.items))) +
		dimStyle.Render(fmt.Sprintf("   (%d marked done)", len(m.done)))

	body := fmt.Sprintf(
		"\n%s\n\n  %s  %s%s\n  %s\n\n  1. Open the rotation page:\n     %s\n  2. Change the credential on the site, then come back.\n\n",
		header,
		titleStyle.Render(it.Credential.Source+" · "+it.Credential.Identity),
		rot, status,
		dimStyle.Render("kind: "+string(it.Credential.Kind)),
		link,
	)

	hints := dimStyle.Render("  ") +
		keyStyle.Render("o") + dimStyle.Render(" open  ") +
		keyStyle.Render("enter") + dimStyle.Render(" mark done & next  ") +
		keyStyle.Render("n/p") + dimStyle.Render(" next/prev  ") +
		keyStyle.Render("s") + dimStyle.Render(" skip  ") +
		keyStyle.Render("q") + dimStyle.Render(" quit") +
		"\n\n" + dimStyle.Render("  Read-only: incredigo enters/stores no secret here.")

	return body + hints + "\n"
}

// Run launches the interactive guide. Requires a TTY; for headless use, generate a
// worklist file instead (incredigo worklist).
func Run(items []worklist.Item) error {
	if len(items) == 0 {
		fmt.Println("No credentials discovered — nothing to rotate.")
		return nil
	}
	_, err := tea.NewProgram(New(items)).Run()
	return err
}

// openURL opens a link in the user's browser, best-effort.
func openURL(url string) tea.Cmd {
	return func() tea.Msg {
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "darwin":
			cmd = exec.Command("open", url)
		case "windows":
			cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
		default:
			cmd = exec.Command("xdg-open", url)
		}
		_ = cmd.Start() // best-effort; ignore on headless/no-DE
		return nil
	}
}
