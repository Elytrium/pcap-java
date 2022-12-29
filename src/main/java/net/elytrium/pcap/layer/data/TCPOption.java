/*
 * Copyright (C) 2022 Elytrium
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

package net.elytrium.pcap.layer.data;

import java.util.Arrays;

public class TCPOption {

  private final TCPOptionType type;
  private final byte[] value;

  public TCPOption(TCPOptionType type, byte[] value) {
    this.type = type;
    this.value = value;
  }

  public TCPOptionType getType() {
    return this.type;
  }

  public byte[] getValue() {
    return this.value;
  }

  @Override
  public String toString() {
    return "TCPOption{"
        + "type=" + this.type
        + ", value=" + Arrays.toString(this.value)
        + '}';
  }
}
