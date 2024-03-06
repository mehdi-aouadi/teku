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

package tech.pegasys.teku.spec.datastructures.operations;

import java.util.Optional;
import tech.pegasys.teku.infrastructure.ssz.SszContainer;
import tech.pegasys.teku.infrastructure.ssz.SszData;
import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.collections.SszBitlist;

/**
 * Interface used to represent different types of attestations ({@link Attestation} and {@link
 * tech.pegasys.teku.spec.datastructures.state.PendingAttestation})
 */
public interface AttestationContainer extends SszData, SszContainer {
  AttestationData getData();

  default Optional<SszBitlist> getAggregationBits() {
    return Optional.empty();
  }

  default Optional<SszList<SszBitlist>> getAggregationBitsElectra() {
    return Optional.empty();
  }
}
