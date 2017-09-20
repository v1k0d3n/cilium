// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package endpointmanager

import (
	"fmt"
	"sync"

	"github.com/cilium/cilium/pkg/endpoint"

	log "github.com/Sirupsen/logrus"
	go_deadlock "github.com/sasha-s/go-deadlock"
)

var (
	// mutex protects endpoints and endpointsAux
	mutex go_deadlock.RWMutex

	// endpoints is the global list of endpoints indexed by ID. mutex must
	// be held to read and write.
	endpoints    = map[uint16]*endpoint.Endpoint{}
	endpointsAux = map[string]*endpoint.Endpoint{}
)

// Insert inserts the endpoint into the global maps
func Insert(ep *endpoint.Endpoint) {
	mutex.Lock()
	endpoints[ep.ID] = ep
	updateReferences(ep)
	mutex.Unlock()
}

// Lookup looks up the endpoint by prefix id
func Lookup(id string) (*endpoint.Endpoint, error) {
	mutex.RLock()
	defer mutex.RUnlock()

	prefix, eid, err := endpoint.ParseID(id)
	if err != nil {
		return nil, err
	}

	switch prefix {
	case endpoint.CiliumLocalIdPrefix:
		n, _ := endpoint.ParseCiliumID(id)
		return lookupCiliumID(uint16(n)), nil

	case endpoint.CiliumGlobalIdPrefix:
		return nil, fmt.Errorf("Unsupported id format for now")

	case endpoint.ContainerIdPrefix:
		return lookupDockerID(eid), nil

	case endpoint.DockerEndpointPrefix:
		return lookupDockerEndpoint(eid), nil

	case endpoint.ContainerNamePrefix:
		return lookupDockerContainerName(eid), nil

	case endpoint.PodNamePrefix:
		return lookupPodNameLocked(eid), nil

	case endpoint.IPv4Prefix:
		return lookupIPv4(eid), nil

	default:
		return nil, fmt.Errorf("Unknown endpoint prefix %s", prefix)
	}
}

// LookupCiliumID looks up endpoint by endpoint ID
func LookupCiliumID(id uint16) *endpoint.Endpoint {
	mutex.RLock()
	ep := lookupCiliumID(id)
	mutex.RUnlock()
	return ep
}

// LookupDockerID looks up endpoint by Docker ID
func LookupDockerID(id string) *endpoint.Endpoint {
	mutex.RLock()
	ep := lookupDockerID(id)
	mutex.RUnlock()
	return ep
}

// LookupIPv4 looks up endpoint by IPv4 address
func LookupIPv4(ipv4 string) *endpoint.Endpoint {
	mutex.RLock()
	ep := lookupIPv4(ipv4)
	mutex.RUnlock()
	return ep
}

// UpdateReferences makes an endpoint available by all possible reference
// fields as available for this endpoint (containerID, IPv4 address, ...)
func UpdateReferences(ep *endpoint.Endpoint) {
	mutex.Lock()
	updateReferences(ep)
	mutex.Unlock()
}

// LinkContainerID links an endpoint and makes it searchable by Docker ID.
func LinkContainerID(ep *endpoint.Endpoint) {
	mutex.Lock()
	linkContainerID(ep)
	mutex.Unlock()
}

// Remove removes the endpoint from the global maps.
func Remove(ep *endpoint.Endpoint) {
	mutex.Lock()
	defer mutex.Unlock()
	delete(endpoints, ep.ID)

	if ep.DockerID != "" {
		delete(endpointsAux, endpoint.NewID(endpoint.ContainerIdPrefix, ep.DockerID))
	}

	if ep.DockerEndpointID != "" {
		delete(endpointsAux, endpoint.NewID(endpoint.DockerEndpointPrefix, ep.DockerEndpointID))
	}

	if ep.IPv4.String() != "" {
		delete(endpointsAux, endpoint.NewID(endpoint.IPv4Prefix, ep.IPv4.String()))
	}

	if ep.ContainerName != "" {
		delete(endpointsAux, endpoint.NewID(endpoint.ContainerNamePrefix, ep.ContainerName))
	}

	if ep.PodName != "" {
		delete(endpointsAux, endpoint.NewID(endpoint.PodNamePrefix, ep.PodName))
	}
}

// lookupCiliumID looks up endpoint by endpoint ID
func lookupCiliumID(id uint16) *endpoint.Endpoint {
	if ep, ok := endpoints[id]; ok {
		return ep
	}
	return nil
}

func lookupDockerEndpoint(id string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpoint.NewID(endpoint.DockerEndpointPrefix, id)]; ok {
		return ep
	}
	return nil
}

func lookupPodNameLocked(name string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpoint.NewID(endpoint.PodNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

func lookupDockerContainerName(name string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpoint.NewID(endpoint.ContainerNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

func lookupIPv4(ipv4 string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpoint.NewID(endpoint.IPv4Prefix, ipv4)]; ok {
		return ep
	}
	return nil
}

func lookupDockerID(id string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpoint.NewID(endpoint.ContainerIdPrefix, id)]; ok {
		return ep
	}
	return nil
}

func linkContainerID(ep *endpoint.Endpoint) {
	endpointsAux[endpoint.NewID(endpoint.ContainerIdPrefix, ep.DockerID)] = ep
}

// UpdateReferences updates the mappings of various values to their corresponding
// endpoints, such as DockerID, Docker Container Name, Pod Name, etc.
func updateReferences(ep *endpoint.Endpoint) {
	if ep.DockerID != "" {
		linkContainerID(ep)
	}

	if ep.DockerEndpointID != "" {
		endpointsAux[endpoint.NewID(endpoint.DockerEndpointPrefix, ep.DockerEndpointID)] = ep
	}

	if ep.IPv4.String() != "" {
		endpointsAux[endpoint.NewID(endpoint.IPv4Prefix, ep.IPv4.String())] = ep
	}

	if ep.ContainerName != "" {
		endpointsAux[endpoint.NewID(endpoint.ContainerNamePrefix, ep.ContainerName)] = ep
	}

	if ep.PodName != "" {
		endpointsAux[endpoint.NewID(endpoint.PodNamePrefix, ep.PodName)] = ep
	}
}

// TriggerPolicyUpdates calls TriggerPolicyUpdates for each endpoint and
// regenerates as required. During this process, the endpoint list is locked
// and cannot be modified.
// Returns a waiting group that can be used to know when all the endpoints are
// regenerated.
func TriggerPolicyUpdates(owner endpoint.Owner) *sync.WaitGroup {
	var wg sync.WaitGroup

	eps := GetEndpoints()
	wg.Add(len(eps))

	for _, ep := range eps {
		go func(ep *endpoint.Endpoint, wg *sync.WaitGroup) {
			policyChanges, err := ep.TriggerPolicyUpdates(owner)
			if err != nil {
				log.Warningf("Error while handling policy updates for endpoint %s", err)
				ep.LogStatus(endpoint.Policy, endpoint.Failure, err.Error())
			} else {
				ep.LogStatusOK(endpoint.Policy, "Policy regenerated")
			}
			if policyChanges {
				<-ep.Regenerate(owner)
			}
			wg.Done()
		}(ep, &wg)
	}

	return &wg
}

// HasGlobalCT returns true if the endpoints have a global CT, false otherwise.
func HasGlobalCT() bool {
	eps := GetEndpoints()
	for _, e := range eps {
		e.RLock()
		globalCT := e.Consumable != nil && !e.Opts.IsEnabled(endpoint.OptionConntrackLocal)
		e.RUnlock()
		if globalCT {
			return true
		}
	}
	return false
}

// GetEndpoints returns a slice of all endpoints present in endpoint manager.
func GetEndpoints() []*endpoint.Endpoint {
	mutex.RLock()
	eps := []*endpoint.Endpoint{}
	for _, ep := range endpoints {
		eps = append(eps, ep)
	}
	mutex.RUnlock()
	return eps
}
