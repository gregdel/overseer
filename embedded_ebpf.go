package main

import _ "embed"

//go:embed kern.o
var ebpfProg []byte
