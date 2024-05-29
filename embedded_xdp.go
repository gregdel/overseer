package main

import _ "embed"

//go:embed kern.o
var xdpProg []byte
