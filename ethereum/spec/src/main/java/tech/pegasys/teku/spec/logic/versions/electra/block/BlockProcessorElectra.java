/*
 * Copyright Consensys Software Inc., 2024
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package tech.pegasys.teku.spec.logic.versions.electra.block;

import static com.google.common.base.Preconditions.checkArgument;

import it.unimi.dsi.fastutil.ints.IntList;
import java.util.List;
import java.util.Optional;
import tech.pegasys.teku.bls.BLSSignatureVerifier;
import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.collections.SszBitlist;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.cache.CapturingIndexedAttestationCache;
import tech.pegasys.teku.spec.cache.IndexedAttestationCache;
import tech.pegasys.teku.spec.config.SpecConfigDeneb;
import tech.pegasys.teku.spec.datastructures.operations.Attestation;
import tech.pegasys.teku.spec.datastructures.operations.AttestationContainer;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.MutableBeaconState;
import tech.pegasys.teku.spec.logic.common.helpers.BeaconStateMutators;
import tech.pegasys.teku.spec.logic.common.helpers.Predicates;
import tech.pegasys.teku.spec.logic.common.operations.OperationSignatureVerifier;
import tech.pegasys.teku.spec.logic.common.operations.validation.AttestationDataValidator;
import tech.pegasys.teku.spec.logic.common.operations.validation.OperationInvalidReason;
import tech.pegasys.teku.spec.logic.common.operations.validation.OperationValidator;
import tech.pegasys.teku.spec.logic.common.statetransition.blockvalidator.BlockValidationResult;
import tech.pegasys.teku.spec.logic.common.statetransition.exceptions.BlockProcessingException;
import tech.pegasys.teku.spec.logic.common.util.AttestationUtil;
import tech.pegasys.teku.spec.logic.common.util.BeaconStateUtil;
import tech.pegasys.teku.spec.logic.common.util.SyncCommitteeUtil;
import tech.pegasys.teku.spec.logic.common.util.ValidatorsUtil;
import tech.pegasys.teku.spec.logic.versions.altair.helpers.BeaconStateAccessorsAltair;
import tech.pegasys.teku.spec.logic.versions.deneb.block.BlockProcessorDeneb;
import tech.pegasys.teku.spec.logic.versions.deneb.helpers.MiscHelpersDeneb;
import tech.pegasys.teku.spec.schemas.SchemaDefinitionsDeneb;

public class BlockProcessorElectra extends BlockProcessorDeneb {
  public BlockProcessorElectra(
      SpecConfigDeneb specConfig,
      Predicates predicates,
      MiscHelpersDeneb miscHelpers,
      SyncCommitteeUtil syncCommitteeUtil,
      BeaconStateAccessorsAltair beaconStateAccessors,
      BeaconStateMutators beaconStateMutators,
      OperationSignatureVerifier operationSignatureVerifier,
      BeaconStateUtil beaconStateUtil,
      AttestationUtil attestationUtil,
      ValidatorsUtil validatorsUtil,
      OperationValidator operationValidator,
      SchemaDefinitionsDeneb schemaDefinitions) {
    super(
        specConfig,
        predicates,
        miscHelpers,
        syncCommitteeUtil,
        beaconStateAccessors,
        beaconStateMutators,
        operationSignatureVerifier,
        beaconStateUtil,
        attestationUtil,
        validatorsUtil,
        operationValidator,
        schemaDefinitions);
  }

  @Override
  public void processAttestations(
      final MutableBeaconState state,
      final SszList<Attestation> attestations,
      final BLSSignatureVerifier signatureVerifier)
      throws BlockProcessingException {
    final CapturingIndexedAttestationCache indexedAttestationCache =
        IndexedAttestationCache.capturing();
    processAttestationsNoVerification(state, attestations, indexedAttestationCache);

    final BlockValidationResult result =
        verifyAttestationSignatures(
            state, attestations, signatureVerifier, indexedAttestationCache);
    if (!result.isValid()) {
      throw new BlockProcessingException(result.getFailureReason());
    }
  }

  @Override
  protected void processAttestationsNoVerification(
      MutableBeaconState state,
      SszList<Attestation> attestations,
      IndexedAttestationCache indexedAttestationCache)
      throws BlockProcessingException {
    final IndexedAttestationProvider indexedAttestationProvider =
        createIndexedAttestationProvider(state, indexedAttestationCache);
    safelyProcess(
        () -> {
          for (Attestation attestation : attestations) {
            // Validate
            assertAttestationValid(state, attestation);
            processAttestation(state, attestation, indexedAttestationProvider);
          }
        });
  }

  @Override
  protected void assertAttestationValid(
      final MutableBeaconState state, final AttestationContainer attestation) {
    super.assertAttestationValid(state, attestation);
    final List<UInt64> committeeIndices = attestation.getCommitteeIndices().orElseThrow();
    final UInt64 committeeCountPerSlot =
        beaconStateAccessors.getCommitteeCountPerSlot(
            state, attestation.getData().getTarget().getEpoch());
    final SszList<SszBitlist> aggregationBits = attestation.getAggregationBitsElectraRequired();
    checkArgument(
        committeeIndices.size() == aggregationBits.size(),
        AttestationDataValidator.AttestationInvalidReason.COMMITTEE_INDICES_MISMATCH);
    final Optional<OperationInvalidReason> committeeCheckResult =
        checkCommittees(
            committeeIndices,
            committeeCountPerSlot,
            state,
            attestation.getData().getSlot(),
            aggregationBits);
    if (committeeCheckResult.isPresent()) {
      throw new IllegalArgumentException(committeeCheckResult.get().describe());
    }
  }

  private Optional<OperationInvalidReason> checkCommittees(
      final List<UInt64> committeeIndices,
      final UInt64 committeeCountPerSlot,
      final BeaconState state,
      final UInt64 slot,
      final SszList<SszBitlist> aggregationBits) {
    for (int index = 0; index < committeeIndices.size(); index++) {
      final UInt64 committeeIndex = committeeIndices.get(index);
      if (committeeIndex.compareTo(committeeCountPerSlot) < 0) {
        return Optional.of(
            AttestationDataValidator.AttestationInvalidReason.COMMITTEE_INDEX_TOO_HIGH);
      }
      final IntList committee =
          beaconStateAccessors.getBeaconCommittee(state, slot, committeeIndex);
      if (committee.size() != aggregationBits.get(index).size()) {
        return Optional.of(
            AttestationDataValidator.AttestationInvalidReason.COMMITTEE_COUNT_MISMATCH);
      }
    }
    return Optional.empty();
  }
}
