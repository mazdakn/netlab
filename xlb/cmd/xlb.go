package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/mazdakn/netlab/xlb/pkg/config"
	"github.com/sirupsen/logrus"
)

func setupSignals() chan struct{} {
	stopC := make(chan struct{})
	signalC := make(chan os.Signal, 1)
	signal.Notify(signalC, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		signal := <-signalC
		logrus.Infof("Received singal %v", signal)
		close(stopC)
	}()

	return stopC
}

func main() {
	logrus.Info("Running xlb")
	_ = config.New()
	//stopC := setupSignals()
}
