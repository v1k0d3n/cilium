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

package kafka

import (
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/optiopay/kafka/proto"
	log "github.com/sirupsen/logrus"
)

func produceTopicContained(neededTopic string, topics []proto.ProduceReqTopic) bool {
	log.Debugf("Looking for topic %q in %+v", neededTopic, topics)
	for _, topic := range topics {
		if topic.Name == neededTopic {
			return true
		}
	}

	return false
}

func matchProduceReq(req *proto.ProduceReq, rule api.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.Topic != "" && !produceTopicContained(rule.Topic, req.Topics) {
		log.Debugf("denied (topic)")
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	log.Debugf("allowed produce")
	return true
}

func fetchTopicContained(neededTopic string, topics []proto.FetchReqTopic) bool {
	for _, topic := range topics {
		if topic.Name == neededTopic {
			return true
		}
	}

	return false
}

func matchFetchReq(req *proto.FetchReq, rule api.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.Topic != "" && !fetchTopicContained(rule.Topic, req.Topics) {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func offsetTopicContained(neededTopic string, topics []proto.OffsetReqTopic) bool {
	for _, topic := range topics {
		if topic.Name == neededTopic {
			return true
		}
	}

	return false
}

func matchOffsetReq(req *proto.OffsetReq, rule api.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.Topic != "" && !offsetTopicContained(rule.Topic, req.Topics) {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func topicContained(neededTopic string, topics []string) bool {
	for _, topic := range topics {
		if topic == neededTopic {
			return true
		}
	}

	return false
}

func matchMetadataReq(req *proto.MetadataReq, rule api.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.Topic != "" && !topicContained(rule.Topic, req.Topics) {
		log.Debugf("Denied (topic)")
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	log.Debugf("allowed metadata")
	return true
}

func offsetCommitTopicContained(neededTopic string, topics []proto.OffsetCommitReqTopic) bool {
	for _, topic := range topics {
		if topic.Name == neededTopic {
			return true
		}
	}

	return false
}

func matchOffsetCommitReq(req *proto.OffsetCommitReq, rule api.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.Topic != "" && !offsetCommitTopicContained(rule.Topic, req.Topics) {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func offsetFetchTopicContained(neededTopic string, topics []proto.OffsetFetchReqTopic) bool {
	for _, topic := range topics {
		if topic.Name == neededTopic {
			return true
		}
	}

	return false
}

func matchOffsetFetchReq(req *proto.OffsetFetchReq, rule api.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.Topic != "" && !offsetFetchTopicContained(rule.Topic, req.Topics) {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func (req *RequestMessage) ruleMatches(rule api.PortRuleKafka) bool {
	log.Debugf("Matching rule %q", rule)

	if req == nil {
		return false
	}

	log.Debugf("Required API key: %d", rule.GetAPIKey())
	if rule.GetAPIKey() != -1 {
		if rule.GetAPIKey() != req.kind {
			log.Debugf("denied (apikey)")
			return false
		}

		log.Debugf("API key matches")
	}

	if rule.GetAPIVersion() != 0 && rule.GetAPIVersion() != req.version {
		log.Debugf("denied (version)")
		return false
	}

	if rule.Topic == "" && rule.ClientID == "" {
		log.Debugf("allowed (no topic or client restriction)")
		return true
	}

	if req.request == nil {
		log.Debugf("Denied (unparseable)")
		return false
	}

	switch val := req.request.(type) {
	case *proto.ProduceReq:
		log.Debugf("Matching produce request")
		return matchProduceReq(val, rule)
	case *proto.FetchReq:
		return matchFetchReq(val, rule)
	case *proto.OffsetReq:
		return matchOffsetReq(val, rule)
	case *proto.MetadataReq:
		return matchMetadataReq(val, rule)
	case *proto.OffsetCommitReq:
		return matchOffsetCommitReq(val, rule)
	case *proto.OffsetFetchReq:
		return matchOffsetFetchReq(val, rule)
	case *proto.ConsumerMetadataReq:
		return true
	}

	log.Debugf("Allowing (default)")
	// If all conditions have been met, allow the request
	return true
}

// MatchesRule validates the Kafka request message against the provided list of
// rules. The function will return true if the policy allows the message,
// otherwise false is returned.
func (req *RequestMessage) MatchesRule(rules []api.PortRuleKafka) bool {
	for _, rule := range rules {
		if req.ruleMatches(rule) {
			return true
		}
	}

	return false
}
