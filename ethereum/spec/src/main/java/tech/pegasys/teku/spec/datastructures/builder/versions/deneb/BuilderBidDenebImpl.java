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

package tech.pegasys.teku.spec.datastructures.builder.versions.deneb;

import java.util.Optional;
import org.apache.tuweni.units.bigints.UInt256;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.containers.Container4;
import tech.pegasys.teku.infrastructure.ssz.primitive.SszUInt256;
import tech.pegasys.teku.infrastructure.ssz.tree.TreeNode;
import tech.pegasys.teku.spec.datastructures.execution.ExecutionPayloadHeader;
import tech.pegasys.teku.spec.datastructures.execution.versions.electra.ExecutionRequests;
import tech.pegasys.teku.spec.datastructures.type.SszKZGCommitment;
import tech.pegasys.teku.spec.datastructures.type.SszPublicKey;

public class BuilderBidDenebImpl
    extends Container4<
        BuilderBidDenebImpl,
        ExecutionPayloadHeader,
        SszList<SszKZGCommitment>,
        SszUInt256,
        SszPublicKey>
    implements BuilderBidDeneb {

  BuilderBidDenebImpl(final BuilderBidSchemaDeneb schema, final TreeNode backingNode) {
    super(schema, backingNode);
  }

  public BuilderBidDenebImpl(
      final BuilderBidSchemaDeneb schema,
      final ExecutionPayloadHeader header,
      final SszList<SszKZGCommitment> blobKzgCommitments,
      final SszUInt256 value,
      final SszPublicKey publicKey) {
    super(schema, header, blobKzgCommitments, value, publicKey);
  }

  @Override
  public ExecutionPayloadHeader getHeader() {
    return getField0();
  }

  @Override
  public Optional<ExecutionRequests> getOptionalExecutionRequests() {
    return Optional.empty();
  }

  @Override
  public SszList<SszKZGCommitment> getBlobKzgCommitments() {
    return getField1();
  }

  @Override
  public UInt256 getValue() {
    return getField2().get();
  }

  @Override
  public BLSPublicKey getPublicKey() {
    return getField3().getBLSPublicKey();
  }
}
