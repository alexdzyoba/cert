package main

import (
	"io/ioutil"
	"log"
	"os"
)

func main() {
	filename := os.Args[1]

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	dump(data)
}
