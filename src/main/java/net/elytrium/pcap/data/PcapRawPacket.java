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

package net.elytrium.pcap.data;

import java.nio.ByteBuffer;
import java.util.Objects;

public class PcapRawPacket {

  private final PcapPacketHeader header;
  private final ByteBuffer byteBuffer;

  public PcapRawPacket(PcapPacketHeader header, ByteBuffer byteBuffer) {
    this.header = header;
    this.byteBuffer = byteBuffer;
  }

  public PcapPacketHeader getHeader() {
    return this.header;
  }

  public ByteBuffer getByteBuffer() {
    return this.byteBuffer;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || this.getClass() != o.getClass()) {
      return false;
    }

    PcapRawPacket that = (PcapRawPacket) o;

    if (!Objects.equals(this.header, that.header)) {
      return false;
    }

    return Objects.equals(this.byteBuffer, that.byteBuffer);
  }

  @Override
  public int hashCode() {
    int result = this.header != null ? this.header.hashCode() : 0;
    result = 31 * result + (this.byteBuffer != null ? this.byteBuffer.hashCode() : 0);
    return result;
  }

  @Override
  public String toString() {
    return "PcapRawPacket{"
        + "header=" + this.header
        + ", byteBuffer=" + this.byteBuffer
        + '}';
  }
}
