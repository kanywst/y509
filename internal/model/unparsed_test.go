package model

import (
	"errors"
	"strings"
	"testing"

	"charm.land/bubbles/v2/list"
	"github.com/kanywst/y509/pkg/certificate"
)

func failureFixture() certificate.ParseFailure {
	return certificate.ParseFailure{
		Block: 1,
		Raw:   []byte{0x30, 0x03, 0x02, 0x01, 0x00},
		Err:   errors.New("x509: malformed certificate"),
	}
}

func modelWithUnparsed(t *testing.T, certCount int) *Model {
	t.Helper()

	m := NewModel(createTestCertificates(certCount), loadTestConfig(t))
	m.SetDimensions(120, 40)
	m.SetReady(true)
	m.SetUnparsed([]certificate.ParseFailure{failureFixture()})
	return m
}

// TestUnparsedRowsAreListedAfterTheCertificates is the point of the row: the
// list is the only complete account of what the input held, and without it a
// bundle silently shows fewer entries than the file has.
func TestUnparsedRowsAreListedAfterTheCertificates(t *testing.T) {
	m := modelWithUnparsed(t, 2)

	items := m.list.Items()
	if len(items) != 3 {
		t.Fatalf("list holds %d rows, want 2 certificates plus 1 unreadable block", len(items))
	}
	if _, ok := items[2].(unparsedItem); !ok {
		t.Errorf("last row is %T, want an unparsedItem", items[2])
	}
	// The certificates keep their positions, which is what makes the index
	// mapping in selectedUnparsed correct.
	for i := 0; i < 2; i++ {
		if _, ok := items[i].(certItem); !ok {
			t.Errorf("row %d is %T, want a certItem", i, items[i])
		}
	}
}

func TestSelectedUnparsedFindsTheRowUnderTheCursor(t *testing.T) {
	m := modelWithUnparsed(t, 2)

	m.list.Select(0)
	if _, ok := m.selectedUnparsed(); ok {
		t.Error("a certificate row reported itself as unreadable")
	}

	m.list.Select(2)
	failure, ok := m.selectedUnparsed()
	if !ok {
		t.Fatal("the unreadable row did not report itself")
	}
	if failure.Block != 1 {
		t.Errorf("block = %d, want 1", failure.Block)
	}
}

// TestUnparsedRowSurvivesAFilter keeps the row from being filtered away: a
// filter asks a question about a certificate and there is none here to answer
// it, so hiding the row would put the reader back where they started.
func TestUnparsedRowSurvivesAFilter(t *testing.T) {
	m := modelWithUnparsed(t, 3)

	filtered := *m
	filtered.certificates = nil
	filtered.list.SetItems(toListItems(filtered.certificates, filtered.unparsed))

	items := filtered.list.Items()
	if len(items) != 1 {
		t.Fatalf("a filter matching nothing left %d rows, want the unreadable one", len(items))
	}
	if _, ok := items[0].(unparsedItem); !ok {
		t.Errorf("remaining row is %T, want the unreadable block", items[0])
	}
}

// TestUnparsedDetailExplainsItself covers the pane that replaces the tabs,
// which have nothing to show for a row with no certificate behind it.
func TestUnparsedDetailExplainsItself(t *testing.T) {
	m := modelWithUnparsed(t, 1)
	m.list.Select(1)

	got := m.renderTabContent(100)
	for _, want := range []string{"could not be parsed", "block 1", "5 bytes", "malformed certificate"} {
		if !strings.Contains(got, want) {
			t.Errorf("detail pane does not mention %q:\n%s", want, got)
		}
	}
}

// TestCommandsRefuseAnUnreadableRow checks the three handlers that act on a
// certificate. Each one used to index straight into m.certificates, which is
// what a row with nothing behind it would have walked off the end of.
func TestCommandsRefuseAnUnreadableRow(t *testing.T) {
	commands := map[string]func(Model) Model{
		"validate": func(m Model) Model { return m.handleValidateCommand() },
		"export":   func(m Model) Model { return m.handleExportCommand("out.pem") },
	}

	for name, run := range commands {
		t.Run(name, func(t *testing.T) {
			m := modelWithUnparsed(t, 1)
			m.list.Select(1)

			got := run(*m)
			if !strings.Contains(got.popupMessage, "could not be parsed") {
				t.Errorf("%s did not explain the unreadable row: %q", name, got.popupMessage)
			}
		})
	}

	t.Run("yank", func(t *testing.T) {
		m := modelWithUnparsed(t, 1)
		m.list.Select(1)

		got, cmd := m.handleYankCommand()
		if !strings.Contains(got.popupMessage, "could not be parsed") {
			t.Errorf("yank did not explain the unreadable row: %q", got.popupMessage)
		}
		// Nothing may reach the clipboard: there is no certificate to copy.
		if cmd != nil {
			t.Error("yank returned a command for a row with no certificate")
		}
	})
}

// TestDelegateRendersAnUnreadableRow guards the renderer the list calls for
// every visible row.
func TestDelegateRendersAnUnreadableRow(t *testing.T) {
	m := modelWithUnparsed(t, 1)
	m.list.Select(1)

	// The row is truncated to the subject column, so the list needs a width
	// for the assertion to be about the content rather than the truncation.
	m.list.SetSize(60, 10)

	var sb strings.Builder
	delegate := certDelegate{styles: m.Styles, warnDays: 30}
	delegate.Render(&sb, m.list, 1, unparsedItem{failure: failureFixture()})

	if !strings.Contains(sb.String(), "unreadable certificate #2") {
		t.Errorf("row does not name the block:\n%s", sb.String())
	}
}

var _ list.Item = unparsedItem{}
