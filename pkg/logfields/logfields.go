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

	// REVIEW Should this match pkg/proxy/accesslog.FieldFilePath ?
	Path = "path"

	K8sNode               = "ciliumNode"
	K8sNodeID             = "ciliumNodeID"
	K8sSvcName            = "k8sSvcName"
	K8sPodName            = "k8sPodName"
	K8sSvcType            = "k8sSvcType"
	K8sNamespace          = "k8sNamespace"
	K8sIdentityAnnotation = "k8sIdentityAnnotation"
	K8sNetworkPolicyName  = "k8sNetworkPolicyName"
	K8sNetworkPolicy      = "k8sNetworkPolicy"
	K8sIngress            = "k8sIngress"
	K8sIngressName        = "k8sIngressName"
	K8sLabels             = "k8sLabels"
	IPTableRule           = "ipTableRule"
	IPAddr                = "ipAddr"
	Port                  = "port"
	Protocol              = "protocol"
	V4Prefix              = "v4Prefix"
	V6Prefix              = "v6Prefix"

	ServiceName      = "serviceName"
	ServiceSHA       = "serviceSHA"
	ServiceNamespace = "serviceNamespace"
	ServiceType      = "serviceType"
	ServiceID        = "serviceID"
	ServicePortID    = "servicePortID"
	Service          = "service"
	LBBackend        = "lbBackend"

	CiliumNetworkPolicyName = "ciliumNetworkPolicyName"
	CiliumNetworkPolicy     = "ciliumNetworkPolicy"

	CiliumNode     = "ciliumNode"
	CiliumID       = "ciliumNodeID"
	CiliumRuleName = "ciliumRuleName"

	BPFServiceKey = "bpfServiceKey"
	BPFService    = "bpfService"
)
