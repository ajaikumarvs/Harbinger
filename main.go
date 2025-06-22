package main

import (
	"log"

	"github.com/ajaikumarvs/harbinger/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
