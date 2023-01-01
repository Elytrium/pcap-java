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

package net.elytrium.pcap.layer;

import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.Map;
import net.elytrium.pcap.layer.data.IpProtocol;
import net.elytrium.pcap.layer.exception.LayerDecodeException;
import net.elytrium.pcap.layer.exception.LayerEncodeException;

public class IPv6ExtOptions extends IPv6Header {

  protected int headerExtLength;
  protected Map<Integer, byte[]> options;

  @Override
  public void decode(ByteBuffer buffer) throws LayerDecodeException {
    if (buffer.remaining() < 8) {
      throw new LayerDecodeException("Hop-by-hop extension header is too small.");
    }

    int position = buffer.position();
    this.nextHeader = IpProtocol.values()[Byte.toUnsignedInt(buffer.get())];
    this.headerExtLength = Byte.toUnsignedInt(buffer.get());
    position += 8 + this.headerExtLength * 8;
    if (buffer.limit() < position) {
      throw new LayerDecodeException("Invalid hop-by-hop extension header.");
    }

    this.options = new LinkedHashMap<>();
    while (buffer.position() < position) {
      if (position - buffer.position() < 2) {
        buffer.position(position);
        break;
      }

      int type = Byte.toUnsignedInt(buffer.get());
      int length = Byte.toUnsignedInt(buffer.get());
      byte[] value = new byte[length];
      buffer.get(value);
      this.options.put(type, value);
    }
  }

  @Override
  public void encode(ByteBuffer buffer) throws LayerEncodeException {
    int size = this.getSize();
    if (buffer.remaining() < size) {
      throw new LayerEncodeException("ByteBuffer is too small.");
    }

    final int position = buffer.position() + size;
    buffer.put((byte) this.nextHeader.ordinal());
    buffer.put((byte) this.headerExtLength);
    this.options.forEach((id, value) -> {
      buffer.put(id.byteValue());
      buffer.put((byte) value.length);
      buffer.put(value);
    });

    buffer.put(new byte[position - buffer.position()]);
  }

  @Override
  public int getSize() {
    int optionsSize = this.options.values().stream().mapToInt(value -> 2 + value.length).sum();
    return (2 + optionsSize) + 7 & ~0x7;
  }

  public int getHeaderExtLength() {
    return this.headerExtLength;
  }

  public void setHeaderExtLength(int headerExtLength) {
    this.headerExtLength = headerExtLength;
  }

  public Map<Integer, byte[]> getOptions() {
    return this.options;
  }

  public void setOptions(Map<Integer, byte[]> options) {
    this.options = options;
  }

  @Override
  public String toString() {
    return "IPv6ExtOptions{"
        + "headerExtLength=" + this.headerExtLength
        + ", options=" + this.options
        + ", nextHeader=" + this.nextHeader
        + '}';
  }
}
