package main

import (
	"fmt"
	"io"
	"os"
)

func flog(w io.Writer, prefix, format string, a ...any) {
	p := fmt.Sprintf("%11s: ", prefix)
	fmt.Fprintf(w, p+format, a...)
}

func logInfo(prefix, format string, a ...any) {
	flog(os.Stdout, prefix, format, a...)
}

func logErr(prefix, format string, a ...any) {
	flog(os.Stderr, prefix, format, a...)
}
