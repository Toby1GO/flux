package socket

import (
	"os"

	"github.com/go-gost/x/config"
)

func saveConfig() {

	file := "agent.json"

	f, err := os.Create(file)
	if err != nil {
		return
	}
	defer f.Close()

	if err := config.Global().Write(f, "json"); err != nil {

		return
	}

	return
}
