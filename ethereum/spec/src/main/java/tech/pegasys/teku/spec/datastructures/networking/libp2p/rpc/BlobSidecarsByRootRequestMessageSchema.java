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

package tech.pegasys.teku.spec.datastructures.networking.libp2p.rpc;

import tech.pegasys.teku.infrastructure.ssz.schema.impl.AbstractSszListSchema;
import tech.pegasys.teku.infrastructure.ssz.tree.TreeNode;
import tech.pegasys.teku.spec.config.SpecConfigDeneb;

public class BlobSidecarsByRootRequestMessageSchema
    extends AbstractSszListSchema<BlobIdentifier, BlobSidecarsByRootRequestMessage> {

  // Size validation according to the spec (MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK) is
  // done in the RPC handler
  public BlobSidecarsByRootRequestMessageSchema(final SpecConfigDeneb specConfigDeneb) {
    super(
        BlobIdentifier.SSZ_SCHEMA,
        (long) specConfigDeneb.getMaxRequestBlocksDeneb()
            * specConfigDeneb.getMaxBlobCommitmentsPerBlock());
  }

  @Override
  public BlobSidecarsByRootRequestMessage createFromBackingNode(final TreeNode node) {
    return new BlobSidecarsByRootRequestMessage(this, node);
  }
}
