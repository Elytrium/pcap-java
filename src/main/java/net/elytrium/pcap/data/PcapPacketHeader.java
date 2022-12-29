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

public class PcapPacketHeader {

  private final long address;
  private final long seconds;
  private final long microseconds;
  private final int captureLength;
  private final int length;

  public PcapPacketHeader(long address, long seconds, long microseconds, int captureLength, int length) {
    this.address = address;
    this.seconds = seconds;
    this.microseconds = microseconds;
    this.captureLength = captureLength;
    this.length = length;
  }

  public long getAddress() {
    return this.address;
  }

  public long getSeconds() {
    return this.seconds;
  }

  public long getMicroseconds() {
    return this.microseconds;
  }

  public int getCaptureLength() {
    return this.captureLength;
  }

  public int getLength() {
    return this.length;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || this.getClass() != o.getClass()) {
      return false;
    }

    PcapPacketHeader that = (PcapPacketHeader) o;

    if (this.address != that.address) {
      return false;
    }

    if (this.seconds != that.seconds) {
      return false;
    }

    if (this.microseconds != that.microseconds) {
      return false;
    }

    if (this.captureLength != that.captureLength) {
      return false;
    }

    return this.length == that.length;
  }

  @Override
  public int hashCode() {
    int result = (int) (this.address ^ (this.address >>> 32));
    result = 31 * result + (int) (this.seconds ^ (this.seconds >>> 32));
    result = 31 * result + (int) (this.microseconds ^ (this.microseconds >>> 32));
    result = 31 * result + this.captureLength;
    result = 31 * result + this.length;
    return result;
  }

  @Override
  public String toString() {
    return "PcapPacketHeader{"
        + "address=" + this.address
        + ", seconds=" + this.seconds
        + ", microseconds=" + this.microseconds
        + ", captureLength=" + this.captureLength
        + ", length=" + this.length
        + '}';
  }

  public static PcapPacketHeader read(long address) {
    if (address == 0) {
      return null;
    }

    MemoryReader reader = new MemoryReader(address);
    return new PcapPacketHeader(
        address,
        reader.readLong(),
        reader.readLong(),
        reader.readInt(),
        reader.readInt()
    );
  }
}
