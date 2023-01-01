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
import java.util.function.Supplier;
import net.elytrium.pcap.layer.exception.LayerDecodeException;
import net.elytrium.pcap.layer.exception.LayerEncodeException;

public class UDP implements Layer {

  private static final int SIZE = 8;

  private int srcPort;
  private int dstPort;
  private int length;
  private short checksum;

  @Override
  public void decode(ByteBuffer buffer) throws LayerDecodeException {
    if (buffer.remaining() < SIZE) {
      throw new LayerDecodeException("UDP header is too small.");
    }

    this.srcPort = Short.toUnsignedInt(buffer.getShort());
    this.dstPort = Short.toUnsignedInt(buffer.getShort());
    this.length = Short.toUnsignedInt(buffer.getShort());
    this.checksum = buffer.getShort();
  }

  @Override
  public void encode(ByteBuffer buffer) throws LayerEncodeException {
    if (buffer.remaining() < SIZE) {
      throw new LayerEncodeException("ByteBuffer is too small.");
    }

    buffer.putShort((short) this.srcPort);
    buffer.putShort((short) this.dstPort);
    buffer.putShort((short) this.length);
    buffer.putShort(this.checksum);
  }

  @Override
  public int getSize() {
    return SIZE;
  }

  @Override
  public Supplier<Layer> nextLayer() {
    return null;
  }

  public int getSrcPort() {
    return this.srcPort;
  }

  public void setSrcPort(int srcPort) {
    this.srcPort = srcPort;
  }

  public int getDstPort() {
    return this.dstPort;
  }

  public void setDstPort(int dstPort) {
    this.dstPort = dstPort;
  }

  public int getLength() {
    return this.length;
  }

  public void setLength(int length) {
    this.length = length;
  }

  public short getChecksum() {
    return this.checksum;
  }

  public void setChecksum(short checksum) {
    this.checksum = checksum;
  }

  @Override
  public String toString() {
    return "UDP{"
        + "srcPort=" + this.srcPort
        + ", dstPort=" + this.dstPort
        + ", length=" + this.length
        + ", checksum=" + this.checksum
        + '}';
  }
}
