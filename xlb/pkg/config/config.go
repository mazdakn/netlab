package config

import (
	"flag"
	"os"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type virtualServer struct {
	Name     string   `yaml:"name,omitempty"`
	Addr     string   `yaml:"addr,omitempty"`
	Backends []string `yaml:"backends,omitempty"`
}

type Config struct {
	VirtualServers []virtualServer `yaml:"virtualServers,omitempty"`
}

func Parse() *Config {
	filePtr := flag.String("config", "", "Configuration file")
	flag.Parse()

	file := *filePtr
	if file == "" {
		logrus.Fatal("Invalid config file name")
	}

	bytes, err := os.ReadFile(file)
	if err != nil {
		logrus.Fatal("Failed to read the config file")
	}
	var conf Config
	err = yaml.Unmarshal(bytes, &conf)

	// TOOD: set log level to debug
	logrus.Infof("Parsed config from command line: %v", conf)
	return &conf
}
