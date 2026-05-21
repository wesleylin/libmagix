# libmagix

A lightweight, pure Go implementation of the `libmagic` file identification engine. `libmagix` parses standard magic files and builds a recursive rule tree to identify file types and MIME types based on binary signatures.

## Features

- **Tree-based Matching:** Implements hierarchical matching (Levels 0, 1, 2+) for high precision (e.g., identifying a `.docx` inside a generic Zip structure).
- **Pure Go:** No CGO dependencies. Easy to cross-compile.
- **Magdir Compatible:** Designed to load and parse standard magic definition files.

## Installation

```bash
go get [github.com/wesleylin/libmagix](https://github.com/wesleylin/libmagix)

go test ./...
```

## Quick start

```
package main

import (
    "fmt"
    "[github.com/wesleylin/libmagix](https://github.com/wesleylin/libmagix)"
)

func main() {
    // 1. Initialize the engine by pointing to your magic definitions folder
    m, err := libmagix.New("./magic/Magdir")
    if err != nil {
        panic(err)
    }

    // 2. Provide some file bytes
    data := []byte("%PDF-1.4\n...")

    // 3. Identify the file
    result := m.Identify(data)
    if result != nil {
        fmt.Printf("Description: %s\n", result.Message)
        fmt.Printf("MIME Type:   %s\n", result.Mime)
    } else {
        fmt.Println("Unknown file type")
    }
}
```

running 

go run cmd/main.go testdata/sample.docx

## How it Works

libmagix follows a three-step process to identify files:

1. Loading: The Loader walks through a directory of magic files.
2. Parsing: The Parser converts flat magic lines into a recursive Rule tree.
3. Matching: The Engine performs a depth-first search on the tree, checking byte offsets and values against the input data.

magic files come from https://github.com/file/file/tree/master/magic/Magdir

## Supported Features

The engine is generic and follows the `libmagic` specification. While it can theoretically parse any rule, it currently has only been tested for PDFs, ELF binaries, BMP images, and Shell scripts.

## Supported Types

Currently supports:

- string (exact byte sequence matching)
- !:mime (MIME type attribution)
- In Progress: belong, lelong, short, byte
