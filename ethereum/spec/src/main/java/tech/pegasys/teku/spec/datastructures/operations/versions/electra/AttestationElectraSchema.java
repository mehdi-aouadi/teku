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

package tech.pegasys.teku.spec.datastructures.operations.versions.electra;

import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.infrastructure.ssz.SszList;
import tech.pegasys.teku.infrastructure.ssz.collections.SszBitlist;
import tech.pegasys.teku.infrastructure.ssz.collections.SszBitvector;
import tech.pegasys.teku.infrastructure.ssz.containers.ContainerSchema4;
import tech.pegasys.teku.infrastructure.ssz.schema.SszListSchema;
import tech.pegasys.teku.infrastructure.ssz.schema.collections.SszBitlistSchema;
import tech.pegasys.teku.infrastructure.ssz.schema.collections.SszBitvectorSchema;
import tech.pegasys.teku.infrastructure.ssz.tree.TreeNode;
import tech.pegasys.teku.spec.config.SpecConfig;
import tech.pegasys.teku.spec.datastructures.operations.AttestationContainerSchema;
import tech.pegasys.teku.spec.datastructures.operations.AttestationData;
import tech.pegasys.teku.spec.datastructures.type.SszSignature;
import tech.pegasys.teku.spec.datastructures.type.SszSignatureSchema;

public class AttestationElectraSchema
    extends ContainerSchema4<
        AttestationElectra, SszList<SszBitlist>, AttestationData, SszBitvector, SszSignature>
    implements AttestationContainerSchema<AttestationElectra> {

  public AttestationElectraSchema(final SpecConfig specConfig) {
    super(
        "Attestation",
        namedSchema(
            "aggregation_bits",
            SszListSchema.create(
                SszBitlistSchema.create(specConfig.getMaxValidatorsPerCommittee()),
                specConfig.getMaxCommitteesPerSlot())),
        namedSchema("data", AttestationData.SSZ_SCHEMA),
        namedSchema(
            "committee_bits", SszBitvectorSchema.create(specConfig.getMaxCommitteesPerSlot())),
        namedSchema("signature", SszSignatureSchema.INSTANCE));
  }

  @SuppressWarnings("unchecked")
  public SszListSchema<SszList<SszBitvector>, ?> getAggregationBitsSchema() {
    return (SszListSchema<SszList<SszBitvector>, ?>) getFieldSchema0();
  }

  @Override
  public AttestationElectra createFromBackingNode(TreeNode node) {
    return new AttestationElectra(this, node);
  }

  public AttestationElectra create(
      final SszList<SszBitlist> aggregationBits,
      final AttestationData data,
      final SszBitvector committeeBits,
      final BLSSignature signature) {
    return new AttestationElectra(this, aggregationBits, data, committeeBits, signature);
  }
}
