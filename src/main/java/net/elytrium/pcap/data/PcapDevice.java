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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import net.elytrium.pcap.memory.MemoryReader;

public class PcapDevice {

  private final String name;
  private final String description;
  private final List<PcapAddress> addresses;
  private final int flags;

  public PcapDevice(String name, String description, List<PcapAddress> addresses, int flags) {
    this.name = name;
    this.description = description;
    this.addresses = addresses;
    this.flags = flags;
  }

  public String getName() {
    return this.name;
  }

  public String getDescription() {
    return this.description;
  }

  public List<PcapAddress> getAddresses() {
    return this.addresses;
  }

  public int getFlags() {
    return this.flags;
  }

  public boolean isLoopback() {
    return (this.flags & 0x01) != 0;
  }

  public boolean isUp() {
    return (this.flags & 0x02) != 0;
  }

  public boolean isRunning() {
    return (this.flags & 0x04) != 0;
  }

  public boolean isWireless() {
    return (this.flags & 0x08) != 0;
  }

  public ConnectionStatus getConnectionStatus() {
    return ConnectionStatus.fromFlags(this.flags);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    PcapDevice that = (PcapDevice) o;

    if (this.flags != that.flags) {
      return false;
    }

    if (!Objects.equals(this.name, that.name)) {
      return false;
    }

    if (!Objects.equals(this.description, that.description)) {
      return false;
    }

    return Objects.equals(this.addresses, that.addresses);
  }

  @Override
  public int hashCode() {
    int result = this.name != null ? this.name.hashCode() : 0;
    result = 31 * result + (this.description != null ? this.description.hashCode() : 0);
    result = 31 * result + (this.addresses != null ? this.addresses.hashCode() : 0);
    result = 31 * result + this.flags;
    return result;
  }

  @Override
  public String toString() {
    return "PcapDevice{"
        + "name='" + this.name + '\''
        + ", description='" + this.description + '\''
        + ", addresses=" + this.addresses
        + ", flags=" + this.flags
        + '}';
  }

  public static List<PcapDevice> read(long address) {
    List<PcapDevice> devices = new ArrayList<>();
    long next = address;
    while (next != 0) {
      MemoryReader reader = new MemoryReader(next);
      next = reader.readAddress();
      String name = reader.readString();
      String description = reader.readString();
      List<PcapAddress> addresses = PcapAddress.read(reader.readAddress());
      int flags = reader.readInt();
      devices.add(new PcapDevice(name, description, addresses, flags));
    }

    return devices;
  }
}
