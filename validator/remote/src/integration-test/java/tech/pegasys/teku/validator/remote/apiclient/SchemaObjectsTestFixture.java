/*
 * Copyright Consensys Software Inc., 2025
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

package tech.pegasys.teku.validator.remote.apiclient;

import static tech.pegasys.teku.spec.config.SpecConfig.FAR_FUTURE_EPOCH;

import tech.pegasys.teku.api.response.v1.beacon.GenesisData;
import tech.pegasys.teku.api.response.v1.beacon.GetGenesisResponse;
import tech.pegasys.teku.api.response.v1.beacon.ValidatorResponse;
import tech.pegasys.teku.api.response.v1.beacon.ValidatorStatus;
import tech.pegasys.teku.api.schema.Attestation;
import tech.pegasys.teku.api.schema.BLSPubKey;
import tech.pegasys.teku.api.schema.SignedAggregateAndProof;
import tech.pegasys.teku.api.schema.SignedVoluntaryExit;
import tech.pegasys.teku.api.schema.SubnetSubscription;
import tech.pegasys.teku.api.schema.Validator;
import tech.pegasys.teku.api.schema.altair.SyncCommitteeContribution;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.TestSpecFactory;
import tech.pegasys.teku.spec.util.DataStructureUtil;

public class SchemaObjectsTestFixture {

  private final DataStructureUtil dataStructureUtil;

  public SchemaObjectsTestFixture(final Spec spec) {
    this.dataStructureUtil = new DataStructureUtil(spec);
  }

  public SchemaObjectsTestFixture() {
    this(TestSpecFactory.createMinimalPhase0());
  }

  public GetGenesisResponse getGenesisResponse() {
    return new GetGenesisResponse(
        new GenesisData(
            dataStructureUtil.randomUInt64(),
            dataStructureUtil.randomBytes32(),
            dataStructureUtil.randomBytes4()));
  }

  public SignedVoluntaryExit signedVoluntaryExit() {
    return new SignedVoluntaryExit(dataStructureUtil.randomSignedVoluntaryExit());
  }

  public ValidatorResponse validatorResponse() {
    return validatorResponse(dataStructureUtil.randomLong(), dataStructureUtil.randomPublicKey());
  }

  public ValidatorResponse validatorResponse(final long index, final BLSPublicKey publicKey) {
    return new ValidatorResponse(
        UInt64.valueOf(index),
        dataStructureUtil.randomUInt64(),
        ValidatorStatus.active_ongoing,
        new Validator(
            new BLSPubKey(publicKey),
            dataStructureUtil.randomBytes32(),
            dataStructureUtil.randomUInt64(),
            false,
            UInt64.ZERO,
            UInt64.ZERO,
            FAR_FUTURE_EPOCH,
            FAR_FUTURE_EPOCH));
  }

  public SyncCommitteeContribution syncCommitteeContribution(final UInt64 slot) {
    final Spec altairSpec = TestSpecFactory.createMainnetAltair();
    final DataStructureUtil altairData = new DataStructureUtil(altairSpec);
    return new SyncCommitteeContribution(altairData.randomSyncCommitteeContribution(slot));
  }

  public Attestation attestation() {
    return new Attestation(dataStructureUtil.randomAttestation());
  }

  public SubnetSubscription subnetSubscription() {
    return new SubnetSubscription(1, UInt64.ONE);
  }

  public SignedAggregateAndProof signedAggregateAndProof() {
    return new SignedAggregateAndProof(dataStructureUtil.randomSignedAggregateAndProof());
  }
}
