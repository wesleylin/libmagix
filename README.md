[![Go CI Status](https://github.com/wesleylin/libmagix/actions/workflows/go.yml/badge.svg)](https://github.com/wesleylin/libmagix/actions)

# libmagix

A pure Go file identification engine, in the style of `libmagic`. It parses magic definitions and matches them against file bytes. The `magix` command ships with an embedded [file(1) Magdir](https://github.com/file/file/tree/master/magic/Magdir) database.

## Install

Download a release from [GitHub Releases](https://github.com/wesleylin/libmagix/releases). Each archive contains the `magix` binary.

| File | System |
| --- | --- |
| `libmagix_darwin_arm64.tar.gz` | macOS, Apple Silicon |
| `libmagix_darwin_amd64.tar.gz` | macOS, Intel |
| `libmagix_linux_arm64.tar.gz` | Linux, arm64 |
| `libmagix_linux_amd64.tar.gz` | Linux, amd64 |
| `libmagix_windows_arm64.zip` | Windows, arm64 |
| `libmagix_windows_amd64.zip` | Windows, amd64 |

On macOS or Linux:

```bash
tar -xzf libmagix_darwin_arm64.tar.gz
./magix testdata/sample.pdf
```

Or install with Go:

```bash
go install github.com/wesleylin/libmagix/cmd/magix@latest
```

The binary uses the embedded database. Pass `-m` to load a magic file or directory from disk instead.

```
magix [-v] [-b] [-i] [-m magic] file...
```

- `-b` prints the description without the filename
- `-i` prints the MIME type
- `-m` loads a magic file or directory from disk
- `-v` prints debug logs

## Library

```bash
go get github.com/wesleylin/libmagix
```

`New` loads a magic file or a directory from disk. A directory named `Magdir` is limited to the names listed in a sibling `allowlist` file.

```go
package main

import (
	"fmt"

	"github.com/wesleylin/libmagix"
)

func main() {
	m, err := libmagix.New("magic/Magdir", nil)
	if err != nil {
		panic(err)
	}

	result := m.Identify([]byte("%PDF-1.4\n"))
	if result == nil {
		fmt.Println("unknown")
		return
	}
	fmt.Println(result.Message)
	fmt.Println(result.Mime)
}
```

From this repo:

```bash
go test ./...
go run ./cmd/magix testdata/sample.docx
```
