package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"time"
)

func main() {
	procname := flag.String("name", "main", "The name of the executable to launch (argv[0]).")
	target := flag.String("target", "", "The absolute path to the executable to launch.")
	config := flag.String("config", "", "A JSON file to read arguments from.")

	flag.Parse()

	args := flag.Args()

	if *config != "" {
		var jsonArgs map[string]string

		configData, err := ioutil.ReadFile(*config)
		if err != nil {
			log.Fatal("Could not read config", err)
		}

		if err := json.Unmarshal(configData, &jsonArgs); err != nil {
			log.Fatal("Could not parse config", err)
		}

		for key, value := range jsonArgs {
			args = append(args, key, value)
		}
	}

	for {
		fmt.Println("Starting", *procname, "with arguments", args)
		cmd := exec.Command(*target, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
		fmt.Println("Command exited, trying again...")
		time.Sleep(time.Second)
	}
}
