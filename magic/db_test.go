package magic

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/wesleylin/libmagix"
)

func TestEmbeddedDatabaseIdentifiesPDF(t *testing.T) {
	m, err := libmagix.NewFS(FS, "Magdir", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	got := m.Identify([]byte("%PDF-1.4\n"))
	if got == nil || !strings.Contains(got.Message, "PDF") {
		t.Fatalf("Identify() = %#v, want a PDF description", got)
	}
}
