// Package magic is the vendored file(1) database embedded in the magix command.
package magic

import "embed"

// FS contains Magdir and the sibling allowlist that gates it.
//
//go:embed Magdir
//go:embed allowlist
var FS embed.FS
