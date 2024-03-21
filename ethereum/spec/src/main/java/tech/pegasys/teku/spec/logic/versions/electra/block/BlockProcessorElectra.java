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
import static tech.pegasys.teku.spec.config.SpecConfig.FAR_FUTURE_EPOCH;
import static tech.pegasys.teku.spec.config.SpecConfigElectra.FULL_EXIT_REQUEST_AMOUNT;

import it.unimi.dsi.fastutil.ints.IntList;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import tech.pegasys.teku.bls.BLSSignatureVerifier;
import tech.pegasys.teku.infrastructure.bytes.Bytes20;
import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.SszMutableList;
import tech.pegasys.teku.infrastructure.ssz.collections.SszBitlist;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszUInt64;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.cache.CapturingIndexedAttestationCache;
import tech.pegasys.teku.spec.cache.IndexedAttestationCache;
import tech.pegasys.teku.spec.config.SpecConfigElectra;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.BeaconBlockBody;
import tech.pegasys.teku.spec.datastructures.execution.ExecutionPayload;
import tech.pegasys.teku.spec.datastructures.execution.versions.electra.DepositReceipt;
import tech.pegasys.teku.spec.datastructures.execution.versions.electra.ExecutionLayerWithdrawalRequest;
import tech.pegasys.teku.spec.datastructures.execution.versions.electra.ExecutionPayloadElectra;
import tech.pegasys.teku.spec.datastructures.operations.Attestation;
import tech.pegasys.teku.spec.datastructures.operations.AttestationContainer;
import tech.pegasys.teku.spec.datastructures.state.Validator;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.MutableBeaconState;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.electra.BeaconStateElectra;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.versions.electra.MutableBeaconStateElectra;
import tech.pegasys.teku.spec.datastructures.state.versions.electra.PendingPartialWithdrawal;
import tech.pegasys.teku.spec.logic.common.helpers.BeaconStateMutators.ValidatorExitContext;
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
import tech.pegasys.teku.spec.logic.versions.electra.helpers.BeaconStateMutatorsElectra;
import tech.pegasys.teku.spec.logic.versions.electra.helpers.PredicatesElectra;
import tech.pegasys.teku.spec.schemas.SchemaDefinitionsElectra;

public class BlockProcessorElectra extends BlockProcessorDeneb {

  private final SpecConfigElectra specConfigElectra;
  private final PredicatesElectra predicatesElectra;
  private final BeaconStateMutatorsElectra beaconStateMutatorsElectra;
  private final SchemaDefinitionsElectra schemaDefinitionsElectra;

  public BlockProcessorElectra(
      final SpecConfigElectra specConfig,
      final Predicates predicates,
      final MiscHelpersDeneb miscHelpers,
      final SyncCommitteeUtil syncCommitteeUtil,
      final BeaconStateAccessorsAltair beaconStateAccessors,
      final BeaconStateMutatorsElectra beaconStateMutators,
      final OperationSignatureVerifier operationSignatureVerifier,
      final BeaconStateUtil beaconStateUtil,
      final AttestationUtil attestationUtil,
      final ValidatorsUtil validatorsUtil,
      final OperationValidator operationValidator,
      final SchemaDefinitionsElectra schemaDefinitions) {
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
    this.specConfigElectra = specConfig;
    this.predicatesElectra = PredicatesElectra.required(predicates);
    this.beaconStateMutatorsElectra = beaconStateMutators;
    this.schemaDefinitionsElectra = schemaDefinitions;
  }

  @Override
  protected void processOperationsNoValidation(
      final MutableBeaconState state,
      final BeaconBlockBody body,
      final IndexedAttestationCache indexedAttestationCache)
      throws BlockProcessingException {
    super.processOperationsNoValidation(state, body, indexedAttestationCache);

    safelyProcess(
        () ->
            processDepositReceipts(
                state,
                body.getOptionalExecutionPayload()
                    .flatMap(ExecutionPayload::toVersionElectra)
                    .map(ExecutionPayloadElectra::getDepositReceipts)
                    .orElseThrow(
                        () ->
                            new BlockProcessingException(
                                "Deposit receipts were not found during block processing."))));
  }

  @Override
  protected void verifyOutstandingDepositsAreProcessed(
      final BeaconState state, final BeaconBlockBody body) {
    final UInt64 eth1DepositIndexLimit =
        state
            .getEth1Data()
            .getDepositCount()
            .min(BeaconStateElectra.required(state).getDepositReceiptsStartIndex());

    if (state.getEth1DepositIndex().isLessThan(eth1DepositIndexLimit)) {
      final int expectedDepositCount =
          Math.min(
              specConfig.getMaxDeposits(),
              eth1DepositIndexLimit.minus(state.getEth1DepositIndex()).intValue());

      checkArgument(
          body.getDeposits().size() == expectedDepositCount,
          "process_operations: Verify that outstanding deposits are processed up to the maximum number of deposits");
    } else {
      checkArgument(
          body.getDeposits().isEmpty(),
          "process_operations: Verify that former deposit mechanism has been disabled");
    }
  }

  @Override
  protected void processExecutionLayerWithdrawalRequests(
      final MutableBeaconState state,
      final Optional<ExecutionPayload> executionPayload,
      final Supplier<ValidatorExitContext> validatorExitContextSupplier)
      throws BlockProcessingException {
    this.processExecutionLayerWithdrawalRequests(
        state,
        getExecutionLayerWithdrawalRequestsFromBlock(executionPayload),
        validatorExitContextSupplier);
  }

  /**
   * Implements process_execution_layer_withdrawal_request from consensus-specs (EIP-7002 &
   * EIP-7251).
   */
  @Override
  public void processExecutionLayerWithdrawalRequests(
      final MutableBeaconState state,
      final SszList<ExecutionLayerWithdrawalRequest> withdrawalRequests,
      final Supplier<ValidatorExitContext> validatorExitContextSupplier)
      throws BlockProcessingException {
    final UInt64 currentEpoch = miscHelpers.computeEpochAtSlot(state.getSlot());

    withdrawalRequests.forEach(
        withdrawalRequest -> {
          // If partial withdrawal queue is full, only full exits are processed
          final boolean isFullExitRequest =
              withdrawalRequest.getAmount().equals(FULL_EXIT_REQUEST_AMOUNT);
          final boolean partialWithdrawalsQueueFull =
              state.toVersionElectra().orElseThrow().getPendingPartialWithdrawals().size()
                  >= specConfigElectra.getPendingPartialWithdrawalsLimit();
          if (partialWithdrawalsQueueFull && !isFullExitRequest) {
            return;
          }

          final Optional<Integer> maybeValidatorIndex =
              validatorsUtil.getValidatorIndex(state, withdrawalRequest.getValidatorPublicKey());
          if (maybeValidatorIndex.isEmpty()) {
            return;
          }

          final int validatorIndex = maybeValidatorIndex.get();
          final Validator validator = state.getValidators().get(validatorIndex);

          // Check if validator has an execution address set
          final boolean hasExecutionAddress =
              predicatesElectra.hasExecutionWithdrawalCredential(validator);
          if (!hasExecutionAddress) {
            return;
          }

          // Check withdrawalRequest source_address matches validator eth1 withdrawal credentials
          final Bytes20 executionAddress =
              new Bytes20(validator.getWithdrawalCredentials().slice(12));
          final boolean isCorrectSourceAddress =
              executionAddress.equals(withdrawalRequest.getSourceAddress());
          if (!isCorrectSourceAddress) {
            return;
          }

          // Check if validator is active
          final boolean isValidatorActive = predicates.isActiveValidator(validator, currentEpoch);
          if (!isValidatorActive) {
            return;
          }

          // Check if validator has already initiated exit
          final boolean hasInitiatedExit = !validator.getExitEpoch().equals(FAR_FUTURE_EPOCH);
          if (hasInitiatedExit) {
            return;
          }

          // Check if validator has been active long enough
          final boolean validatorActiveLongEnough =
              currentEpoch.isGreaterThanOrEqualTo(
                  validator.getActivationEpoch().plus(specConfig.getShardCommitteePeriod()));
          if (!validatorActiveLongEnough) {
            return;
          }

          final UInt64 pendingBalanceToWithdraw =
              validatorsUtil.getPendingBalanceToWithdraw(state, validatorIndex);
          if (isFullExitRequest) {
            // Only exit validator if it has no pending withdrawals in the queue
            if (pendingBalanceToWithdraw.isZero()) {
              beaconStateMutators.initiateValidatorExit(
                  state, validatorIndex, validatorExitContextSupplier);
              return;
            }
          }

          final UInt64 validatorBalance = state.getBalances().get(validatorIndex).get();
          final UInt64 minActivationBalance = specConfigElectra.getMinActivationBalance();

          final boolean hasCompoundingWithdrawalCredential =
              predicatesElectra.hasCompoundingWithdrawalCredential(validator);
          final boolean hasSufficientEffectiveBalance =
              validator.getEffectiveBalance().isGreaterThanOrEqualTo(minActivationBalance);
          final boolean hasExcessBalance =
              validatorBalance.isGreaterThan(minActivationBalance.plus(pendingBalanceToWithdraw));
          if (hasCompoundingWithdrawalCredential
              && hasSufficientEffectiveBalance
              && hasExcessBalance) {
            final UInt64 toWithdraw =
                validatorBalance
                    .min(minActivationBalance)
                    .minus(pendingBalanceToWithdraw)
                    .min(withdrawalRequest.getAmount());
            final UInt64 exitQueueEpoch =
                beaconStateMutatorsElectra.computeExitEpochAndUpdateChurn(
                    MutableBeaconStateElectra.required(state), toWithdraw);
            final UInt64 withdrawableEpoch =
                exitQueueEpoch.plus(specConfigElectra.getMinValidatorWithdrawabilityDelay());

            // Add the partial withdrawal to the pending queue
            final SszMutableList<PendingPartialWithdrawal> newPendingPartialWithdrawals =
                MutableBeaconStateElectra.required(state)
                    .getPendingPartialWithdrawals()
                    .createWritableCopy();
            newPendingPartialWithdrawals.append(
                schemaDefinitionsElectra
                    .getPendingPartialWithdrawalSchema()
                    .create(
                        SszUInt64.of(UInt64.fromLongBits(validatorIndex)),
                        SszUInt64.of(toWithdraw),
                        SszUInt64.of(withdrawableEpoch)));
            MutableBeaconStateElectra.required(state)
                .setPendingPartialWithdrawals(newPendingPartialWithdrawals);
          }
        });
  }

  private SszList<ExecutionLayerWithdrawalRequest> getExecutionLayerWithdrawalRequestsFromBlock(
      final Optional<ExecutionPayload> maybeExecutionPayload) throws BlockProcessingException {
    return maybeExecutionPayload
        .flatMap(ExecutionPayload::toVersionElectra)
        .map(ExecutionPayloadElectra::getWithdrawalRequests)
        .orElseThrow(
            () ->
                new BlockProcessingException(
                    "Execution layer withdrawal requests were not found during block processing."));
  }

  /*
   Implements process_deposit_receipt from consensus-specs (EIP-6110)
  */
  @Override
  public void processDepositReceipts(
      final MutableBeaconState state, final SszList<DepositReceipt> depositReceipts)
      throws BlockProcessingException {
    final MutableBeaconStateElectra electraState = MutableBeaconStateElectra.required(state);
    for (DepositReceipt depositReceipt : depositReceipts) {
      // process_deposit_receipt
      if (electraState
          .getDepositReceiptsStartIndex()
          .equals(SpecConfigElectra.UNSET_DEPOSIT_RECEIPTS_START_INDEX)) {
        electraState.setDepositReceiptsStartIndex(depositReceipt.getIndex());
      }
      applyDeposit(
          state,
          depositReceipt.getPubkey(),
          depositReceipt.getWithdrawalCredentials(),
          depositReceipt.getAmount(),
          depositReceipt.getSignature(),
          Optional.empty(),
          false);
    }
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
