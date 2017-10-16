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

package endpoint

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/cilium/cilium/common"
	log "github.com/sirupsen/logrus"
)

type labelArrays map[policy.NumericIdentity]labels.LabelArray

func (e *Endpoint) checkEgressAccess(owner Owner, dstLabels labels.LabelArray, opts models.ConfigurationMap, opt string) {
	ctx := policy.SearchContext{
		From: e.Consumable.LabelArray,
		To:   dstLabels,
	}

	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}

	switch owner.GetPolicyRepository().AllowsLabelAccess(&ctx) {
	case api.Allowed:
		opts[opt] = "enabled"
	case api.Denied:
		opts[opt] = "disabled"
	}
}

// allowConsumer must be called with global endpoint.Mutex held
func (e *Endpoint) allowConsumer(owner Owner, id policy.NumericIdentity) bool {
	cache := policy.GetConsumableCache()
	if !e.Opts.IsEnabled(OptionConntrack) {
		return e.Consumable.AllowConsumerAndReverseLocked(cache, id)
	}
	return e.Consumable.AllowConsumerLocked(cache, id)
}

func (e *Endpoint) invalidatePolicy() {
	if e.Consumable != nil {
		// Resetting to 0 will trigger a regeneration on the next update
		log.Debugf("Invalidated policy for endpoint %d", e.ID)
		e.Consumable.Mutex.Lock()
		e.Consumable.Iteration = 0
		e.Consumable.Mutex.Unlock()
	}
}

// ProxyID returns a unique string to identify a proxy mapping
func (e *Endpoint) ProxyID(l4 *policy.L4Filter) string {
	direction := "ingress"
	if !l4.Ingress {
		direction = "egress"
	}
	return fmt.Sprintf("%d:%s:%s:%d", e.ID, direction, l4.Protocol, l4.Port)
}

func (e *Endpoint) addRedirect(owner Owner, l4 *policy.L4Filter) (uint16, error) {
	return owner.UpdateProxyRedirect(e, l4)
}

func (e *Endpoint) cleanUnusedRedirects(owner Owner, oldMap policy.L4PolicyMap, newMap policy.L4PolicyMap) {
	for k, v := range oldMap {
		if newMap != nil {
			// Keep redirects which are also in the new policy
			if _, ok := newMap[k]; ok {
				continue
			}
		}

		if v.IsRedirect() {
			if err := owner.RemoveProxyRedirect(e, &v); err != nil {
				log.Warningf("error while removing proxy: %s", err)
			}

		}
	}
}

func getSecurityIdentities(labelsMap labelArrays, selector *api.EndpointSelector) []policy.NumericIdentity {
	identities := []policy.NumericIdentity{}
	for idx, labels := range labelsMap {
		if selector.Matches(labels) {
			log.Debugf("L4 Policy matches %v.", labels)
			identities = append(identities, idx)
		}
	}

	return identities
}

func (e *Endpoint) removeOldFilter(labelsMap labelArrays, filter *policy.L4Filter) int {
	port := uint16(filter.Port)
	proto, err := u8proto.ParseProtocol(string(filter.Protocol))
	if err != nil {
		log.Warningf("Parse policy protocol failed: %s", err)
		return 1
	}

	errors := 0
	for _, sel := range filter.FromEndpoints {
		for _, id := range getSecurityIdentities(labelsMap, &sel) {
			srcID := id.Uint32()
			if err = e.PolicyMap.DeleteL4(srcID, port, uint8(proto)); err != nil {
				log.Debugf("Delete old l4 policy failed: %s", err)
				errors++
			}
		}
	}

	return errors
}

func (e *Endpoint) applyNewFilter(labelsMap labelArrays, filter *policy.L4Filter) int {
	port := uint16(filter.Port)
	proto, err := u8proto.ParseProtocol(string(filter.Protocol))
	if err != nil {
		log.Warningf("Parse policy protocol failed: %s", err)
		return 1
	}

	errors := 0
	for _, sel := range filter.FromEndpoints {
		for _, id := range getSecurityIdentities(labelsMap, &sel) {
			srcID := id.Uint32()
			if e.PolicyMap.L4Exists(srcID, port, uint8(proto)) {
				log.Debugf("L4 filter exists: %+v", filter)
				continue
			}
			if err = e.PolicyMap.AllowL4(srcID, port, uint8(proto)); err != nil {
				log.Warningf("Update of l4 policy map failed: %s", err)
				errors++
			}
		}
	}

	return errors
}

// Looks for mismatches between 'oldPolicy' and 'newPolicy', and fixes up
// this Endpoint's BPF PolicyMap to reflect the new L3+L4 combined policy.
func (e *Endpoint) applyL4PolicyLocked(labelsMap labelArrays, oldPolicy *policy.L4Policy, newPolicy *policy.L4Policy) error {
	errors := 0

	if oldPolicy != nil {
		for _, filter := range oldPolicy.Ingress {
			errors = e.removeOldFilter(labelsMap, &filter)
		}
	}

	if newPolicy == nil {
		return nil
	}

	for _, filter := range newPolicy.Ingress {
		errors += e.applyNewFilter(labelsMap, &filter)
	}

	if errors > 0 {
		return fmt.Errorf("Some Label+L4 policy updates failed.")
	}
	return nil
}


func getLabelsMap(owner Owner, cache *policy.ConsumableCache, minID, maxID policy.NumericIdentity) (labelArrays, error) {
	labelsMap := map[policy.NumericIdentity]labels.LabelArray{}
	reservedIDs := cache.GetReservedIDs()
	var idx policy.NumericIdentity
	for _, idx = range reservedIDs {
		lbls, err := owner.GetCachedLabelList(idx)
		if err != nil {
			return nil, err
		}
		// Skip currently unused IDs
		if lbls == nil || len(lbls) == 0 {
			continue
		}
		labelsMap[idx] = lbls
	}

	for idx = minID; idx < maxID; idx++ {
		lbls, err := owner.GetCachedLabelList(idx)
		if err != nil {
			return nil, err
		}
		// Skip currently unused IDs
		if lbls == nil || len(lbls) == 0 {
			continue
		}
		labelsMap[idx] = lbls
	}

	return labelsMap, nil
}

// Must be called with global endpoint.Mutex held
func (e *Endpoint) regenerateConsumable(owner Owner, labelsMap labelArrays, repo *policy.Repository, revision uint64, c *policy.Consumable) (bool, error) {
	// Containers without a security label are not accessible
	if c.ID == 0 {
		log.WithFields(log.Fields{
			logfields.EndpointID: e.StringID(),
		}).Warning("Endpoint lacks identity, skipping policy calculation")

		return false, nil
	}

	// Skip consumable recomputation for this consumable is already valid
	if c.Iteration == revision {
		log.Debugf("Reusing cached policy for identity %d", c.ID)
		return false, nil
	}

	ctx := policy.SearchContext{
		To: c.LabelArray,
	}
	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}

	newL4Policy, err := repo.ResolveL4Policy(&ctx)
	if err != nil {
		return false, err
	}

	// No failing after this point.
	changed := false

	// Mark all entries unused by denying them
	for k := range c.Consumers {
		c.Consumers[k].DeletionMark = true
	}

	if !e.L4Policy.PolicyEqual(newL4Policy) {
		if (e.L4Policy == c.L4Policy) {
			if (c.L4Policy != nil) {
				e.cleanUnusedRedirects(owner, c.L4Policy.Ingress, newL4Policy.Ingress)
				e.cleanUnusedRedirects(owner, c.L4Policy.Egress, newL4Policy.Egress)
			}
			c.L4Policy = newL4Policy
		} else {
			// c.L4Policy was already updated
			if !c.L4Policy.PolicyEqual(newL4Policy) {
				log.Fatalf("C/E POLICY MISMATCH!")
			}
		}
		err = e.applyL4PolicyLocked(labelsMap, e.L4Policy, c.L4Policy)
		if err != nil {
			return false, err
		}
		e.L4Policy = c.L4Policy // Reuse the common policy
		changed = true
	}

	if newL4Policy.HasRedirect() || owner.AlwaysAllowLocalhost() {
		if e.allowConsumer(owner, policy.ReservedIdentityHost) {
			changed = true
		}
	}

	for srcID, srcLabels := range labelsMap {
		ctx.From = srcLabels
		log.Debugf("[%s] Evaluating context %+v", e.PolicyID(), ctx)

		if repo.AllowsLabelAccess(&ctx) == api.Allowed {
			if e.allowConsumer(owner, srcID) {
				changed = true
			}
		}
	}

	// Garbage collect all unused entries
	for _, val := range c.Consumers {
		if val.DeletionMark {
			val.DeletionMark = false
			c.BanConsumerLocked(val.ID)
			changed = true
		}
	}

	// Result is valid until cache iteration advances
	c.Iteration = revision

	log.Debugf("[%s] Iteration %d: new consumable %d, consumers = %+v (changed :%d)",
		e.PolicyID(), c.Iteration, c.ID, c.Consumers, changed)

	return changed, nil
}

// Must be called with global repo.Mutrex, e.Mutex, and c.Mutex held
func (e *Endpoint) regenerateL3Policy(owner Owner, repo *policy.Repository, revision uint64, c *policy.Consumable) bool {

	ctx := policy.SearchContext{
		To: c.LabelArray, // keep c.Mutex taken to protect this.
	}
	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}
	newL3policy := repo.ResolveL3Policy(&ctx)

	if e.L3Policy.PolicyEqual(newL3policy) {
		log.Debugf("[%s] Iteration %d: No change in CIDR policy.", e.PolicyID(), revision)
		return false
	}

	e.L3Policy = newL3policy
	return true
}

// regeneratePolicy regenerates endpoints policy if needed and returns
// whether the BPF for the given endpoint should be regenerated. Only
// called when e.Consumable != nil.
//
// In a typical workflow this is first called to regenerate the policy
// (if needed), and second time when the BPF program is
// regenerated. The second step is usually unnecessary and may be
// optimized away by the revision checks.  However, if there has been
// a further policy update between the first and second calls, the
// second call will update the policy just before regenerating the BPF
// programs to avoid needing to regenerate BPF programs aging right
// after.
//
// Policy changes are tracked so that only endpoints affected by the
// policy change need to have their BPF programs regenerated.
//
// Policy generation may fail, and in that case we exit before
// actually changing the policy in any way, so that the last policy
// remains fully in effect if the new policy can not be
// implemented. This is done on endpoint-basis, however, and it is
// possible that policy update succeeds for some endpoints, while it
// fails for other endpoints.
func (e *Endpoint) regeneratePolicy(owner Owner) (bool, error) {
	log.Debugf("[%s] Starting regenerate...", e.PolicyID())

	opts := make(models.ConfigurationMap)

	repo := owner.GetPolicyRepository()
	repo.Mutex.RLock()
	revision := repo.GetRevision()
	defer repo.Mutex.RUnlock()

	// Recompute policy for this endpoint only if not already done for this revision.
	if e.policyRevision >= revision || e.nextPolicyRevision >= revision {
		// This revision already computed, but may still need to be applied to BPF
		return e.nextPolicyRevision > e.policyRevision, nil
	}

	c := e.Consumable

	// We may update the consumable, so keep it locked
	c.Mutex.Lock()
	defer c.Mutex.Unlock()

	// Collect label arrays before policy computation, as this can fail.
	cache := policy.GetConsumableCache()
	maxID, err := owner.GetCachedMaxLabelID()
	if err != nil {
		return false, err
	}
	labelsMap, err := getLabelsMap(owner, cache, policy.MinimalNumericIdentity, maxID)
	if err != nil {
		log.Debugf("[%s] Received error while evaluating policy: %s", e.PolicyID(), err)
		return false, err
	}

	policyChanged, err := e.regenerateConsumable(owner, labelsMap, repo, revision, c)
	if err != nil {
		return false, err
	}
	// no failures after this point

	if e.regenerateL3Policy(owner, repo, revision, c) {
		policyChanged = true
	}

	e.checkEgressAccess(owner, labelsMap[policy.ReservedIdentityHost], opts, OptionAllowToHost)
	e.checkEgressAccess(owner, labelsMap[policy.ReservedIdentityWorld], opts, OptionAllowToWorld)

	if e.Consumable.L4Policy.RequiresConntrack() {
		opts[OptionConntrack] = "enabled"
	}

	// Changes to this also bump the policy repository revision,
	// so that this too can be skipped if revision has not
	// changed.
	if owner.EnableEndpointPolicyEnforcement(e) {
		opts[OptionPolicy] = "enabled"
	} else {
		opts[OptionPolicy] = "disabled"
	}

	optsChanged := e.ApplyOptsLocked(opts)

	// If we are in this function, then policy has been calculated.
	if !e.PolicyCalculated {
		log.Debugf("setting PolicyCalculated to true for endpoint %d", e.ID)
		e.PolicyCalculated = true
		// Always trigger a regenerate after the first policy
		// calculation has been performed
		policyChanged = true
	}

	log.Debugf("[%s] Done regenerating revision=%v policyChanged=%v optsChanged=%v",
		e.PolicyID(), revision, policyChanged, optsChanged)

	e.nextPolicyRevision = revision
	// If no policy or options change occurred for this endpoint then the endpoint is
	// already running the latest revision, otherwise we have to wait for
	// the regeneration of the endpoint to complete.
	if !(policyChanged || optsChanged) {
		e.policyRevision = revision
	}

	// Return if need to regenerate BPF
	return e.nextPolicyRevision > e.policyRevision, nil
}

// Called with e.Mutex locked
func (e *Endpoint) regenerate(owner Owner) error {
	e.BuildMutex.Lock()
	defer e.BuildMutex.Unlock()

	// If endpoint was marked as disconnected then
	// it won't be regenerated
	if e.IsDisconnecting() {
		log.WithFields(log.Fields{
			logfields.EndpointID: e.StringID(),
		}).Debug("Endpoint disconnected, skipping build")
		return fmt.Errorf("endpoint disconnected, skipping build")
	}

	log.WithFields(log.Fields{
		logfields.EndpointID: e.StringID(),
	}).Debug("Regenerating endpoint...")

	origDir := filepath.Join(owner.GetStateDir(), e.StringID())

	// This is the temporary directory to store the generated headers,
	// the original existing directory is not overwritten until the
	// entire generation process has succeeded.
	tmpDir := origDir + "_next"

	// Create temporary endpoint directory if it does not exist yet
	if err := os.MkdirAll(tmpDir, 0777); err != nil {
		return fmt.Errorf("Failed to create endpoint directory: %s", err)
	}

	e.Mutex.Lock()

	if e.Consumable != nil {
		// Regenerate policy and apply any options resulting in the
		// policy change.
		if _, err := e.regeneratePolicy(owner); err != nil {
			e.Mutex.Unlock()
			return fmt.Errorf("Unable to regenerate policy for '%s': %s",
				e.PolicyMap.String(), err)
		}
	}
	e.Mutex.Unlock()

	if err := e.regenerateBPF(owner, tmpDir); err != nil {
		os.RemoveAll(tmpDir)
		return err
	}

	// Move the current endpoint directory to a backup location
	backupDir := origDir + "_stale"
	if err := os.Rename(origDir, backupDir); err != nil {
		os.RemoveAll(tmpDir)
		return fmt.Errorf("Unable to rename current endpoint directory: %s", err)
	}

	// Make temporary directory the new endpoint directory
	if err := os.Rename(tmpDir, origDir); err != nil {
		os.RemoveAll(tmpDir)

		if err2 := os.Rename(backupDir, origDir); err2 != nil {
			log.WithFields(log.Fields{
				logfields.EndpointID: e.StringID(),
			}).Warningf("Restoring directory %s for endpoint failed, endpoint "+
				"is in inconsistent state. Keeping stale directory.",
				backupDir)
			return err2
		}

		return fmt.Errorf("Restored original endpoint directory, atomic replace failed: %s", err)
	}

	os.RemoveAll(backupDir)

	log.WithFields(log.Fields{
		logfields.EndpointID: e.StringID(),
	}).Info("Regenerated program of endpoint")

	return nil
}

// Regenerate forces the regeneration of endpoint programs & policy
func (e *Endpoint) Regenerate(owner Owner) <-chan bool {
	newReq := &Request{
		ID:           uint64(e.ID),
		MyTurn:       make(chan bool),
		Done:         make(chan bool),
		ExternalDone: make(chan bool),
	}
	owner.QueueEndpointBuild(newReq)
	go func(req *Request, e *Endpoint) {
		buildSuccess := true

		e.Mutex.Lock()
		// If endpoint was marked as disconnected then it won't be
		// regenerated
		if !e.IsDisconnectingLocked() {
			e.State = StateRegenerating
		}
		e.Mutex.Unlock()

		isMyTurn, isMyTurnChanOK := <-req.MyTurn
		if isMyTurnChanOK && isMyTurn {
			log.WithFields(log.Fields{
				logfields.EndpointID: e.StringID(),
			}).Debug("Dequeued endpoint from build queue")

			if err := e.regenerate(owner); err != nil {
				buildSuccess = false
				e.LogStatus(BPF, Failure, err.Error())
			} else {
				buildSuccess = true
				e.SetState(StateReady)
				e.LogStatusOK(BPF, "Successfully regenerated endpoint program")
			}

			req.Done <- buildSuccess
		} else {
			buildSuccess = false

			log.WithFields(log.Fields{
				logfields.EndpointID: e.StringID(),
			}).Debug("My request was cancelled because I'm already in line")
		}
		// The external listener can ignore the channel so we need to
		// make sure we don't block
		select {
		case req.ExternalDone <- buildSuccess:
		default:
		}
		close(req.ExternalDone)
	}(newReq, e)
	return newReq.ExternalDone
}

// TriggerPolicyUpdates indicates that a policy change is likely to
// affect this endpoint. Will update all required endpoint configuration and
// state to reflect new policy.
//
// Returns true if policy was changed and endpoints needs to be rebuilt
func (e *Endpoint) TriggerPolicyUpdates(owner Owner) (bool, error) {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	if e.Consumable == nil {
		return false, nil
	}

	if err := e.l3PolicyValidation(); err != nil {
		return false, err
	}

	changed, err := e.regeneratePolicy(owner)
	if err != nil {
		return changed, fmt.Errorf("%s: %s", e.StringID(), err)
	}

	return changed, err
}

func (e *Endpoint) SetIdentity(owner Owner, id *policy.Identity) {
	repo := owner.GetPolicyRepository()
	cache := policy.GetConsumableCache()

	repo.Mutex.Lock()
	defer repo.Mutex.Unlock()

	if e.Consumable != nil {
		if e.SecLabel != nil && id.ID == e.Consumable.ID {
			e.SecLabel = id
			e.Consumable.Mutex.Lock()
			e.Consumable.Labels = id
			e.Consumable.LabelArray = id.Labels.ToSlice()
			e.Consumable.Mutex.Unlock()
			return
		}
		cache.Remove(e.Consumable)
	}
	e.SecLabel = id
	e.LabelsHash = e.SecLabel.Labels.SHA256Sum()
	e.Consumable = cache.GetOrCreate(id.ID, id)

	if e.State == StateWaitingForIdentity {
		e.State = StateReady
	}

	// Annotate pod that this endpoint represents with its security identity
	go owner.AnnotateEndpoint(e, common.CiliumIdentityAnnotation, e.SecLabel.ID.String())
	e.Consumable.Mutex.RLock()
	log.Debugf("Set identity of EP %d to %d and consumable to %+v", e.ID, id, e.Consumable)
	e.Consumable.Mutex.RUnlock()
}

// l3PolicyValidation prevents code generation failures due to the number of
// CIDR matches
func (e *Endpoint) l3PolicyValidation() error {
	if e.L3Policy == nil {
		return nil
	}
	if l := len(e.L3Policy.Egress.Map); l > api.MaxCIDREntries {
		return fmt.Errorf("too many egress L3 entries %d/%d", l, api.MaxCIDREntries)
	}
	if l := len(e.L3Policy.Ingress.Map); l > api.MaxCIDREntries {
		return fmt.Errorf("too many ingress L3 entries %d/%d", l, api.MaxCIDREntries)
	}
	return nil
}
