package manager

import "net"

type endpoint struct {
	addr net.Addr
	port uint
}

type vServer struct {
	name string
	frontend endpoint
	backends []endpoint
}

type server struct {
	vServers []vServer
}

func New() *server {
	return &server{}
}

func FromConfig(conf config.Config) &server {
	if len(conf.VirtualServers) == 0 {
		logrus.Errorf("No virtual server defined")
		return nil
	}
	for _, s := range conf.VirtualServers {
		ok := validateAddr(s.Addr)
		if !ok {
			logrus.Warnf("Skipping virtual server %v", s.Name)
			continue
		}
		for 
	}
}

func validateAddr(addr string) bool {
	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		logrus.Warnf("Invalid address %v", addr)
		return false
	}

}
