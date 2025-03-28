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

package tech.pegasys.teku.validator.client.loader;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import tech.pegasys.teku.service.serviceutils.layout.DataDirLayout;

abstract class AbstractValidatorSource implements ValidatorSource {
  private static final Logger LOG = LogManager.getLogger();
  protected final boolean readOnly;
  protected final Optional<DataDirLayout> maybeDataDirLayout;

  protected AbstractValidatorSource(
      final boolean readOnly, final Optional<DataDirLayout> maybeDataDirLayout) {
    this.readOnly = readOnly;
    this.maybeDataDirLayout = maybeDataDirLayout;
  }

  void ensureDirectoryExists(final Path path) throws IOException {
    if (!path.toFile().exists() && !path.toFile().mkdirs()) {
      throw new IOException("Unable to create required path: " + path);
    }
  }

  void cleanupIncompleteSave(final Path path) {
    LOG.debug("Cleanup " + path.toString());
    if (path.toFile().exists() && path.toFile().isFile() && !path.toFile().delete()) {
      LOG.warn("Failed to remove {}", path);
    }
  }

  @Override
  public boolean canUpdateValidators() {
    return !readOnly && maybeDataDirLayout.isPresent();
  }
}
