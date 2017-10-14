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

package proxy

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/cilium/cilium/pkg/kafka"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/nodeaddress"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	"github.com/optiopay/kafka/proto"
	log "github.com/sirupsen/logrus"
)

const (
	fieldID = "id"
)

// kafkaRedirect implements the Redirect interface for an l7 proxy
type kafkaRedirect struct {
	// protects all fields of this struct
	lock.RWMutex

	conf     kafkaConfiguration
	epID     uint64
	ingress  bool
	nodeInfo accesslog.NodeAddressInfo
	rules    policy.L7DataMap
	socket   *proxySocket
}

// ToPort returns the redirect port of an OxyRedirect
func (k *kafkaRedirect) ToPort() uint16 {
	return k.conf.listenPort
}

type destLookupFunc func(remoteAddr string, dport uint16) (uint32, string, error)

type kafkaConfiguration struct {
	policy        *policy.L4Filter
	id            string
	source        ProxySource
	listenPort    uint16
	noMarker      bool
	lookupNewDest destLookupFunc
}

// createKafkaRedirect creates a redirect with corresponding proxy
// configuration. This will launch a proxy instance.
func createKafkaRedirect(conf kafkaConfiguration) (Redirect, error) {
	redir := &kafkaRedirect{
		conf:    conf,
		epID:    conf.source.GetID(),
		ingress: conf.policy.Ingress,
		nodeInfo: accesslog.NodeAddressInfo{
			IPv4: nodeaddress.GetExternalIPv4().String(),
			IPv6: nodeaddress.GetIPv6().String(),
		},
	}

	if redir.conf.lookupNewDest == nil {
		redir.conf.lookupNewDest = lookupNewDest
	}

	if err := redir.UpdateRules(conf.policy); err != nil {
		return nil, err
	}

	marker := 0
	if !conf.noMarker {
		marker = GetMagicMark(redir.ingress)

		// As ingress proxy, all replies to incoming requests must have the
		// identity of the endpoint we are proxying for
		if redir.ingress {
			marker |= int(conf.source.GetIdentity())
		}
	}

	// Listen needs to be in the synchronous part of this function to ensure that
	// the proxy port is never refusing connections.
	socket, err := listenSocket(fmt.Sprintf(":%d", redir.conf.listenPort), marker)
	if err != nil {
		return nil, err
	}

	redir.socket = socket

	go func() {
		for {
			pair, err := socket.Accept()
			select {
			case <-socket.closing:
				// Don't report errors while the socket is being closed
				return
			default:
				if err != nil {
					log.WithFields(log.Fields{
						"listenPort": redir.conf.listenPort,
					}).WithError(err).Error("Unable to accept connection")
					continue
				}
			}

			go redir.handleConnection(pair)
		}
	}()

	return redir, nil
}

func (k *kafkaRedirect) canAccess(req *kafka.RequestMessage, srcIdentity uint32) bool {
	rules := k.rules.GetRelevantRules(k.ingress, uint64(srcIdentity))
	b, err := json.Marshal(rules.Kafka)
	out := ""
	if err != nil {
		out = err.Error()
	} else {
		out = string(b)
	}
	log.WithFields(log.Fields{
		"request": req.String(),
	}).Debugf("Applying rules %s", out)
	return req.MatchesRule(rules.Kafka)
}

func (k *kafkaRedirect) handleRequest(pair *connectionPair, req *kafka.RequestMessage) {
	log.WithFields(log.Fields{
		fieldID:   pair.String(),
		"request": req.String(),
	}).Debug("Handling Kafka request")

	addr := pair.rx.conn.RemoteAddr()
	if addr == nil {
		log.Warning("RemoteAddr() is nil")
		return
	}

	// retrieve identity of source together with original destination IP
	// and destination port
	srcIdentity, dstIPPort, err := k.conf.lookupNewDest(addr.String(), k.conf.listenPort)
	if err != nil {
		log.WithFields(log.Fields{
			fieldID:  pair.String(),
			"source": addr.String(),
		}).WithError(err).Error("Unable lookup original destination")
		return
	}

	if !k.canAccess(req, srcIdentity) {
		log.WithFields(log.Fields{
			fieldID: pair.String(),
		}).Debug("Kafka request is denied by policy")

		resp, err := req.CreateResponse(proto.ErrTopicAuthorizationFailed)
		if err != nil {
			log.WithFields(log.Fields{
				fieldID: pair.String(),
			}).WithError(err).Error("Unable to create response message")
			return
		}

		pair.rx.Enqueue(resp.GetRaw())
		return
	}

	marker := 0
	if !k.conf.noMarker {
		marker = GetMagicMark(k.ingress) | int(srcIdentity)
	}

	log.WithFields(log.Fields{
		fieldID:       pair.String(),
		"marker":      marker,
		"destination": dstIPPort,
	}).Debug("Dialing original destination")

	txConn, err := ciliumDialer(marker, addr.Network(), dstIPPort)
	if err != nil {
		log.WithFields(log.Fields{
			fieldID:       pair.String(),
			"origNetwork": addr.Network(),
			"origDest":    dstIPPort,
		}).WithError(err).Error("Unable to dial original destination")
		return
	}

	pair.tx.conn = txConn
	pair.tx.startWriter()
	pair.tx.startReadAndPipe(pair.rx)

	log.WithFields(log.Fields{
		fieldID: pair.String(),
	}).Debug("Forwarding Kafka request")

	// Write the entire raw request onto the outgoing connection
	pair.tx.Enqueue(req.GetRaw())
}

func (k *kafkaRedirect) handleConnection(pair *connectionPair) {
	log.WithFields(log.Fields{
		"from": pair.rx,
		"to":   pair.tx,
	}).Debug("Handling new Kafka connection")

	for {
		req, err := kafka.ReadRequest(pair.rx.conn)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				pair.rx.Close()
				return
			}

			log.WithError(err).Error("Unable to parse Kafka request")
			continue
		} else {
			k.handleRequest(pair, req)
		}
	}
}

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (k *kafkaRedirect) UpdateRules(l4 *policy.L4Filter) error {
	if l4.L7Parser != policy.ParserTypeKafka {
		return fmt.Errorf("invalid type %q, must be of type ParserTypeKafka", l4.L7Parser)
	}

	k.Lock()
	k.rules = policy.L7DataMap{}
	for key, val := range l4.L7RulesPerEp {
		k.rules[key] = val
	}
	k.Unlock()

	return nil
}

// Close the redirect.
func (k *kafkaRedirect) Close() {
	k.socket.Close()
}

func init() {
	proto.ReadMessages = false
}
