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

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import net.elytrium.pcap.memory.MemoryReader;

public class PcapAddress {

  private final InetSocketAddress address;
  private final InetSocketAddress netmask;
  private final InetSocketAddress broadcast;
  private final InetSocketAddress destination;

  public PcapAddress(InetSocketAddress address, InetSocketAddress netmask,
                     InetSocketAddress broadcast, InetSocketAddress destination) {
    this.address = address;
    this.netmask = netmask;
    this.broadcast = broadcast;
    this.destination = destination;
  }

  public InetSocketAddress getAddress() {
    return this.address;
  }

  public InetSocketAddress getNetmask() {
    return this.netmask;
  }

  public InetSocketAddress getBroadcast() {
    return this.broadcast;
  }

  public InetSocketAddress getDestination() {
    return this.destination;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    PcapAddress that = (PcapAddress) o;

    if (!Objects.equals(this.address, that.address)) {
      return false;
    }

    if (!Objects.equals(this.netmask, that.netmask)) {
      return false;
    }

    if (!Objects.equals(this.broadcast, that.broadcast)) {
      return false;
    }

    return Objects.equals(this.destination, that.destination);
  }

  @Override
  public int hashCode() {
    int result = this.address != null ? this.address.hashCode() : 0;
    result = 31 * result + (this.netmask != null ? this.netmask.hashCode() : 0);
    result = 31 * result + (this.broadcast != null ? this.broadcast.hashCode() : 0);
    result = 31 * result + (this.destination != null ? this.destination.hashCode() : 0);
    return result;
  }

  @Override
  public String toString() {
    return "PcapAddress{"
        + "address=" + this.address
        + ", netmask=" + this.netmask
        + ", broadcast=" + this.broadcast
        + ", destination=" + this.destination
        + '}';
  }

  public static List<PcapAddress> read(long address) {
    List<PcapAddress> addresses = new ArrayList<>();
    long next = address;
    while (next != 0) {
      MemoryReader reader = new MemoryReader(next);
      next = reader.readAddress();
      addresses.add(new PcapAddress(
          reader.readSockaddr(),
          reader.readSockaddr(),
          reader.readSockaddr(),
          reader.readSockaddr()
      ));
    }

    return addresses;
  }
}
