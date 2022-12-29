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

public class IPv4Option {

  private final IPv4OptionType type;
  private final byte length;
  private final short value;

  public IPv4Option(IPv4OptionType type, byte length, short value) {
    this.type = type;
    this.length = length;
    this.value = value;
  }

  public IPv4OptionType getType() {
    return this.type;
  }

  public byte getLength() {
    return this.length;
  }

  public short getValue() {
    return this.value;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || this.getClass() != o.getClass()) {
      return false;
    }

    IPv4Option that = (IPv4Option) o;

    if (this.length != that.length) {
      return false;
    }

    if (this.value != that.value) {
      return false;
    }

    return this.type == that.type;
  }

  @Override
  public int hashCode() {
    int result = this.type != null ? this.type.hashCode() : 0;
    result = 31 * result + (int) this.length;
    result = 31 * result + (int) this.value;
    return result;
  }

  @Override
  public String toString() {
    return "IPv4Option{"
        + "type=" + this.type
        + ", length=" + this.length
        + ", value=" + this.value
        + '}';
  }
}
