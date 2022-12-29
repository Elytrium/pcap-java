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
import net.elytrium.pcap.layer.data.IpProtocol;
import net.elytrium.pcap.layer.exception.LayerDecodeException;
import net.elytrium.pcap.layer.exception.LayerEncodeException;

public class IPv6Fragment extends IPv6Header {

  private static final int SIZE = 8;

  private short fragmentOffset;
  private boolean hasMore;
  private int identification;

  @Override
  public void decode(ByteBuffer buffer) throws LayerDecodeException {
    if (buffer.remaining() < SIZE) {
      throw new LayerDecodeException("Fragment extension header is too small.");
    }

    this.nextHeader = IpProtocol.values()[Byte.toUnsignedInt(buffer.get())];
    buffer.get();
    short offsetMore = buffer.getShort();
    this.fragmentOffset = (short) ((offsetMore >>> 3) & 0x1FFF);
    this.hasMore = (offsetMore & 0x01) != 0;
    this.identification = buffer.getInt();
  }

  @Override
  public void encode(ByteBuffer buffer) throws LayerEncodeException {
    if (buffer.remaining() < SIZE) {
      throw new LayerEncodeException("ByteBuffer is too small.");
    }

    buffer.put((byte) this.nextHeader.ordinal());
    buffer.put((byte) 0);
    short offsetMore = (short) (this.fragmentOffset << 3);
    offsetMore |= this.hasMore ? 1 : 0;
    buffer.putShort(offsetMore);
    buffer.putInt(this.identification);
  }

  @Override
  public int getSize() {
    return SIZE;
  }

  public short getFragmentOffset() {
    return this.fragmentOffset;
  }

  public void setFragmentOffset(short fragmentOffset) {
    this.fragmentOffset = fragmentOffset;
  }

  public boolean isHasMore() {
    return this.hasMore;
  }

  public void setHasMore(boolean hasMore) {
    this.hasMore = hasMore;
  }

  public int getIdentification() {
    return this.identification;
  }

  public void setIdentification(int identification) {
    this.identification = identification;
  }

  @Override
  public String toString() {
    return "Fragment{"
        + "fragmentOffset=" + this.fragmentOffset
        + ", hasMore=" + this.hasMore
        + ", identification=" + this.identification
        + ", nextHeader=" + this.nextHeader
        + '}';
  }
}
