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
import java.util.Arrays;
import java.util.function.Supplier;
import net.elytrium.pcap.layer.data.EthernetProtocol;
import net.elytrium.pcap.layer.exception.LayerDecodeException;
import net.elytrium.pcap.layer.exception.LayerEncodeException;

public class Ethernet implements EthernetProtocolHeader {

  private static final int SIZE = 14;

  private byte[] dstAddress;
  private byte[] srcAddress;
  private EthernetProtocol protocol;

  @Override
  public void decode(ByteBuffer buffer) throws LayerDecodeException {
    if (buffer.remaining() < SIZE) {
      throw new LayerDecodeException("Ethernet frame is too small.");
    }

    this.dstAddress = new byte[6];
    buffer.get(this.dstAddress);
    this.srcAddress = new byte[6];
    buffer.get(this.srcAddress);
    int protocol = Short.toUnsignedInt(buffer.getShort());
    this.protocol = EthernetProtocol.getByValue(protocol);
  }

  @Override
  public void encode(ByteBuffer buffer) throws LayerEncodeException {
    if (buffer.remaining() < SIZE) {
      throw new LayerEncodeException("ByteBuffer is too small.");
    }

    buffer.put(this.dstAddress);
    buffer.put(this.srcAddress);
    buffer.putShort((short) this.protocol.getValue());
  }

  @Override
  public int getSize() {
    return SIZE;
  }

  @Override
  public Supplier<Layer> nextLayer() {
    return this.protocol != null ? this.protocol.getLayer() : null;
  }

  public byte[] getDstAddress() {
    return this.dstAddress;
  }

  public void setDstAddress(byte[] dstAddress) {
    this.dstAddress = dstAddress;
  }

  public byte[] getSrcAddress() {
    return this.srcAddress;
  }

  public void setSrcAddress(byte[] srcAddress) {
    this.srcAddress = srcAddress;
  }

  @Override
  public EthernetProtocol getProtocol() {
    return this.protocol;
  }

  @Override
  public void setProtocol(EthernetProtocol protocol) {
    this.protocol = protocol;
  }

  @Override
  public String toString() {
    return "Ethernet{"
        + "dstAddress=" + Arrays.toString(this.dstAddress)
        + ", srcAddress=" + Arrays.toString(this.srcAddress)
        + ", protocol=" + this.protocol
        + '}';
  }
}
