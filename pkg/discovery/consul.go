package discovery

import (
	"github.com/hashicorp/consul/api"
	"log"
	"os"
	"strconv"
)

func InitServiceDiscovery() {
	log.Print("initializing consul client")

	consulClient, err := api.NewClient(
		&api.Config{
			Address: os.Getenv("CONSUL_HOST"),
		},
	)
	if err != nil {
		log.Fatal("error creating consul client")
	}

	log.Print("register service in consul")
	agent := consulClient.Agent()
	parsedPort, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		log.Fatal("port parse error")
	}

	service := &api.AgentServiceRegistration{
		Name:    os.Getenv("CONSUL_SERVICE_NAME"),
		Port:    parsedPort,
		Address: os.Getenv("CONSUL_SERVICE_ADDRESS"),
	}
	err = agent.ServiceRegister(service)
	if err != nil {
		log.Fatalf("error while service registration due to error '%s'", err)
	}
	log.Print("service registered in consul")
}
