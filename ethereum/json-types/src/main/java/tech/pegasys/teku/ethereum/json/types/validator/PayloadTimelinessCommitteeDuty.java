/*
 * Copyright Consensys Software Inc., 2026
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

package tech.pegasys.teku.ethereum.json.types.validator;

import static tech.pegasys.teku.ethereum.json.types.EthereumTypes.PUBLIC_KEY_TYPE;
import static tech.pegasys.teku.infrastructure.json.types.CoreTypes.UINT64_TYPE;

import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.infrastructure.json.types.DeserializableTypeDefinition;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;

public record PayloadTimelinessCommitteeDuty(
    BLSPublicKey publicKey, UInt64 validatorIndex, UInt64 slot) {

  public static final DeserializableTypeDefinition<PayloadTimelinessCommitteeDuty>
      PTC_DUTY_TYPE_DEFINITION =
          DeserializableTypeDefinition.object(
                  PayloadTimelinessCommitteeDuty.class,
                  PayloadTimelinessCommitteeDuty.Builder.class)
              .name("PayloadTimelinessCommitteeDuty")
              .initializer(PayloadTimelinessCommitteeDuty.Builder::new)
              .finisher(PayloadTimelinessCommitteeDuty.Builder::build)
              .withField(
                  "pubkey",
                  PUBLIC_KEY_TYPE,
                  PayloadTimelinessCommitteeDuty::publicKey,
                  PayloadTimelinessCommitteeDuty.Builder::publicKey)
              .withField(
                  "validator_index",
                  UINT64_TYPE,
                  PayloadTimelinessCommitteeDuty::validatorIndex,
                  PayloadTimelinessCommitteeDuty.Builder::validatorIndex)
              .withField(
                  "slot",
                  UINT64_TYPE,
                  PayloadTimelinessCommitteeDuty::slot,
                  PayloadTimelinessCommitteeDuty.Builder::slot)
              .build();

  public static class Builder {

    private BLSPublicKey publicKey;
    private UInt64 validatorIndex;
    private UInt64 slot;

    public Builder publicKey(final BLSPublicKey publicKey) {
      this.publicKey = publicKey;
      return this;
    }

    public Builder validatorIndex(final UInt64 validatorIndex) {
      this.validatorIndex = validatorIndex;
      return this;
    }

    public Builder slot(final UInt64 slot) {
      this.slot = slot;
      return this;
    }

    public PayloadTimelinessCommitteeDuty build() {
      return new PayloadTimelinessCommitteeDuty(publicKey, validatorIndex, slot);
    }
  }
}
