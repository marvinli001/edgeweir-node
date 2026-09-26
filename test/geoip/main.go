package main

import (
	"github.com/marvinli001/edgeweir-node/internal/testutil/geofixture"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: geoip OUTPUT_DIRECTORY")
	}
	if err := os.MkdirAll(os.Args[1], 0755); err != nil {
		log.Fatal(err)
	}
	if _, _, err := geofixture.Write(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}
