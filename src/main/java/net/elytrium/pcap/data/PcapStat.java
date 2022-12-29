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

package net.elytrium.pcap.data;

import net.elytrium.pcap.memory.MemoryReader;

public class PcapStat {

  private final int packetsReceived;
  private final int packetsDropped;
  private final int interfaceDrops;

  public PcapStat(int packetsReceived, int packetsDropped, int interfaceDrops) {
    this.packetsReceived = packetsReceived;
    this.packetsDropped = packetsDropped;
    this.interfaceDrops = interfaceDrops;
  }

  public int getPacketsReceived() {
    return this.packetsReceived;
  }

  public int getPacketsDropped() {
    return this.packetsDropped;
  }

  public int getInterfaceDrops() {
    return this.interfaceDrops;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || this.getClass() != o.getClass()) {
      return false;
    }

    PcapStat pcapStat = (PcapStat) o;

    if (this.packetsReceived != pcapStat.packetsReceived) {
      return false;
    }

    if (this.packetsDropped != pcapStat.packetsDropped) {
      return false;
    }

    return this.interfaceDrops == pcapStat.interfaceDrops;
  }

  @Override
  public int hashCode() {
    int result = this.packetsReceived;
    result = 31 * result + this.packetsDropped;
    result = 31 * result + this.interfaceDrops;
    return result;
  }

  @Override
  public String toString() {
    return "PcapStat{"
        + "packetsReceived=" + this.packetsReceived
        + ", packetsDropped=" + this.packetsDropped
        + ", interfaceDrops=" + this.interfaceDrops
        + '}';
  }

  public static PcapStat read(long address) {
    if (address == 0) {
      return null;
    }

    MemoryReader reader = new MemoryReader(address);
    return new PcapStat(
        reader.readInt(),
        reader.readInt(),
        reader.readInt()
    );
  }
}
