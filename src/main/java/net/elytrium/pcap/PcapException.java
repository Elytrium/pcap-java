/*
 * Copyright (C) 2022 - 2023 Elytrium
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package net.elytrium.pcap;

import net.elytrium.pcap.data.PcapError;

public class PcapException extends Exception {

  private final PcapError error;

  public PcapException() {
    this.error = null;
  }

  public PcapException(String message) {
    super(message);
    this.error = null;
  }

  public PcapException(PcapError error) {
    super(error.toString());
    this.error = error;
  }

  public PcapError getError() {
    return this.error;
  }
}
