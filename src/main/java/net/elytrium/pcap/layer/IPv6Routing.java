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

package net.elytrium.pcap.layer;

import java.nio.ByteBuffer;
import java.util.Arrays;
import net.elytrium.pcap.layer.data.IpProtocol;
import net.elytrium.pcap.layer.exception.LayerDecodeException;
import net.elytrium.pcap.layer.exception.LayerEncodeException;

public class IPv6Routing extends IPv6Header {

  private int headerExtLength;
  private int routingType;
  private int segmentsLeft;
  private byte[] data;

  @Override
  public void decode(ByteBuffer buffer) throws LayerDecodeException {
    if (buffer.remaining() < 8) {
      throw new LayerDecodeException("Routing extension header is too small.");
    }

    this.nextHeader = IpProtocol.values()[Byte.toUnsignedInt(buffer.get())];
    this.headerExtLength = Byte.toUnsignedInt(buffer.get());
    this.routingType = Byte.toUnsignedInt(buffer.get());
    this.segmentsLeft = Byte.toUnsignedInt(buffer.get());
    this.data = new byte[this.headerExtLength * 8];
    buffer.get(this.data);
  }

  @Override
  public void encode(ByteBuffer buffer) throws LayerEncodeException {
    int size = this.getSize();
    if (buffer.remaining() < size) {
      throw new LayerEncodeException("ByteBuffer is too small.");
    }

    int position = buffer.position() + size;
    buffer.put((byte) this.nextHeader.ordinal());
    buffer.put((byte) this.headerExtLength);
    buffer.put((byte) this.routingType);
    buffer.put((byte) this.segmentsLeft);
    buffer.put(new byte[position - buffer.position()]);
  }

  @Override
  public int getSize() {
    return (4 + this.data.length) + 7 & ~0x7;
  }

  public int getHeaderExtLength() {
    return this.headerExtLength;
  }

  public void setHeaderExtLength(int headerExtLength) {
    this.headerExtLength = headerExtLength;
  }

  public int getRoutingType() {
    return this.routingType;
  }

  public void setRoutingType(int routingType) {
    this.routingType = routingType;
  }

  public int getSegmentsLeft() {
    return this.segmentsLeft;
  }

  public void setSegmentsLeft(int segmentsLeft) {
    this.segmentsLeft = segmentsLeft;
  }

  public byte[] getData() {
    return this.data;
  }

  public void setData(byte[] data) {
    this.data = data;
  }

  @Override
  public String toString() {
    return "IPv6Routing{"
        + "headerExtLength=" + this.headerExtLength
        + ", routingType=" + this.routingType
        + ", segmentsLeft=" + this.segmentsLeft
        + ", data=" + Arrays.toString(this.data)
        + ", nextHeader=" + this.nextHeader
        + '}';
  }
}
