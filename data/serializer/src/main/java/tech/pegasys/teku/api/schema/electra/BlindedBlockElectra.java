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

package tech.pegasys.teku.api.schema.electra;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.api.schema.altair.BeaconBlockAltair;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.SpecVersion;
import tech.pegasys.teku.spec.datastructures.blocks.BeaconBlock;
import tech.pegasys.teku.spec.datastructures.blocks.BeaconBlockSchema;

public class BlindedBlockElectra extends BeaconBlockAltair {

  public BlindedBlockElectra(final BeaconBlock message) {
    super(
        message.getSlot(),
        message.getProposerIndex(),
        message.getParentRoot(),
        message.getStateRoot(),
        new BlindedBeaconBlockBodyElectra(
            message.getBody().toBlindedVersionElectra().orElseThrow()));
  }

  @Override
  public BeaconBlockSchema getBeaconBlockSchema(final SpecVersion spec) {
    return spec.getSchemaDefinitions().getBlindedBeaconBlockSchema();
  }

  @Override
  public BeaconBlock asInternalBeaconBlock(final Spec spec) {
    final SpecVersion specVersion = spec.atSlot(slot);
    return getBeaconBlockSchema(specVersion)
        .create(
            slot,
            proposer_index,
            parent_root,
            state_root,
            body.asInternalBeaconBlockBody(specVersion));
  }

  @JsonProperty("body")
  @Override
  public BlindedBeaconBlockBodyElectra getBody() {
    return (BlindedBeaconBlockBodyElectra) body;
  }

  @JsonCreator
  public BlindedBlockElectra(
      @JsonProperty("slot") final UInt64 slot,
      @JsonProperty("proposer_index") final UInt64 proposerIndex,
      @JsonProperty("parent_root") final Bytes32 parentRoot,
      @JsonProperty("state_root") final Bytes32 stateRoot,
      @JsonProperty("body") final BlindedBeaconBlockBodyElectra body) {
    super(slot, proposerIndex, parentRoot, stateRoot, body);
  }
}
