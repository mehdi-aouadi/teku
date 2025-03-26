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

package tech.pegasys.teku.infrastructure.ssz.containers;

import tech.pegasys.teku.infrastructure.ssz.SszData;
import tech.pegasys.teku.infrastructure.ssz.impl.AbstractSszImmutableContainer;
import tech.pegasys.teku.infrastructure.ssz.tree.TreeNode;

/** Autogenerated by tech.pegasys.teku.ssz.backing.ContainersGenerator */
public class /*$$ViewClassName*/ ContainerTemplate /*$$*/<
        C extends
            /*$$ViewClassName*/ ContainerTemplate /*$$*/<C, /*$$ViewTypeNames*/ V0, V1 /*$$*/>,
        /*$$ViewTypes*/ V0 extends SszData,
        V1 extends SszData /*$$*/>
    extends AbstractSszImmutableContainer {

  protected /*$$ViewClassName*/ ContainerTemplate /*$$*/(
      final /*$$TypeClassName*/ ContainerSchemaTemplate /*$$*/<C, /*$$ViewTypeNames*/ V0, V1 /*$$*/>
          schema) {
    super(schema);
  }

  protected /*$$ViewClassName*/ ContainerTemplate /*$$*/(
      final /*$$TypeClassName*/ ContainerSchemaTemplate /*$$*/<C, /*$$ViewTypeNames*/ V0, V1 /*$$*/>
          schema,
      final TreeNode backingNode) {
    super(schema, backingNode);
  }

  protected /*$$ViewClassName*/ ContainerTemplate /*$$*/(
      final /*$$TypeClassName*/ ContainerSchemaTemplate /*$$*/<C, /*$$ViewTypeNames*/ V0, V1 /*$$*/>
          schema, /*$$ViewParams*/
      final V0 arg1,
      final V1 arg2 /*$$*/) {
    super(schema, /*$$ViewArgs*/ arg1, arg2 /*$$*/);
  }

  /*$$Getters*/
  protected V0 getField0() {
    return getAny(0);
  }

  protected V1 getField1() {
    return getAny(1);
  }
  /*$$*/
}
