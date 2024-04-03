package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const (
	defaultAddr string = "localhost:8080"
)

type Subnet struct {
	Id     string `json:"id,omitempty"`
	Family int    `json:"family,omitempty"`
	Cidr   string `json:"cidr,omitempty"`
	ipNet  *net.IPNet
}

type ipamServer struct {
	subnets []Subnet
	address string
}

func newIPAMServer(addr string) *ipamServer {
	return &ipamServer{
		subnets: make([]Subnet, 0),
		address: addr,
	}
}

func (i *ipamServer) Start() {
	// Setup the url handler and start http server
	http.HandleFunc("/subnets", i.subnetHandlers)
	err := http.ListenAndServe(i.address, nil)
	if err != nil {
		logrus.Fatalf("Failed to start the server: %v", err)
		return
	}
	logrus.Infof("Started the server on %v", i.address)
}

func (i *ipamServer) subnetHandlers(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodPost:
		i.postHandler(writer, request)
	case http.MethodGet:
		i.getHandler(writer, request)
	default:
		logrus.Warnf("Unknown request method: %v", request.Method)
	}
}

// postHandler handles all POST requests.
func (i *ipamServer) postHandler(writer http.ResponseWriter, request *http.Request) {
	// Read the request.
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		logrus.WithError(err).Error("Failed to get request body")
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	// Unmarshal the request to Subnet struct.
	var subnet Subnet
	err = json.Unmarshal(body, &subnet)
	if err != nil {
		logrus.WithError(err).Error("Failed to unmarshal request")
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	// Check if the subnet information is valid.
	_, ipnet, err := net.ParseCIDR(subnet.Cidr)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to parse subnet %v", subnet.Cidr)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	// Check if there is already a subnet with conflicting cidr.
	id, foundConflict := i.checkConflicts(ipnet)
	if foundConflict {
		logrus.Errorf("Found conflicts with subnet with uuid %v", id)
		writer.WriteHeader(http.StatusConflict)
		return
	}

	// Create the new subnet.
	subnet.ipNet = ipnet
	subnet.Family = ipVersion(ipnet.IP)
	subnet.Id = uuid.New().String()
	i.subnets = append(i.subnets, subnet)
	logrus.Infof("New subnet created: %v", subnet)
	writer.WriteHeader(http.StatusCreated)
}

// ipVersion detects the subnet version.
func ipVersion(ip net.IP) int {
	if ip.To4() == nil {
		return 6
	}
	return 4
}

// checkConflicts checks for any conflict with already available subnets.
func (i *ipamServer) checkConflicts(ipnet *net.IPNet) (string, bool) {
	for _, s := range i.subnets {
		if s.ipNet.Contains(ipnet.IP) || ipnet.Contains(s.ipNet.IP) {
			return s.Id, true
		}
	}
	return "", false
}

// getHandler handles all GET requests.
func (i *ipamServer) getHandler(writer http.ResponseWriter, request *http.Request) {
	// Marshal the list of subnets to json, and send it as response.
	data, err := json.Marshal(&i.subnets)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal subnet list")
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.Write(data)
}

func main() {
	// Parse arguments and get the address to listen to.
	addrPtr := flag.String("addr", defaultAddr, "Address to bind to")
	flag.Parse()
	addr := *addrPtr

	// Create the IPAM Server and start it.
	ipamSrv := newIPAMServer(addr)
	ipamSrv.Start()
}
