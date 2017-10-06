// Copyright 2017 Authors of Cilium
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

// Package logfields defines common logging fields which are used across packages
package logfields

const (
	// EndpointID is the numeric endpoint identifier
	EndpointID = "endpointID"

	// ContainerID is the container identifier
	ContainerID = "containerID"

	// IdentityLabels are the labels relevant for the security identity
	IdentityLabels = "identityLabels"

	// Identity is the identifier of a security identity
	Identity = "identity"

	// L3PolicyID is the identifier of a L3 Policy
	L3PolicyID = "l3PolicyID"

	// L4PolicyID is the identifier of a L4 Policy
	L4PolicyID = "l4PolicyID"

	K8sPodName            = "k8sPodName"
	K8sNamespace          = "k8sNamespace"
	K8sIdentityAnnotation = "k8sIdentityAnnotation"
	IPTableRule           = "ipTableRule"
	IPAddr                = "ipAddr"
	V4Prefix              = "v4Prefix"
	V6Prefix              = "v6Prefix"
)
