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
import java.util.function.Supplier;
import net.elytrium.pcap.layer.data.EthernetProtocol;
import net.elytrium.pcap.layer.exception.LayerDecodeException;
import net.elytrium.pcap.layer.exception.LayerEncodeException;

public class LinuxSLL implements EthernetProtocolHeader {

  private static final int SIZE = 16;

  public enum PacketType {
    HOST,
    BROADCAST,
    MULTICAST,
    OTHER_HOST,
    OUTGOING,
    LOOPBACK,
    FASTROUTE
  }

  private PacketType packetType;
  private int addressType;
  private int addressLength;
  private byte[] address;
  private EthernetProtocol protocol;

  @Override
  public void decode(ByteBuffer buffer) throws LayerDecodeException {
    if (buffer.remaining() < SIZE) {
      throw new LayerDecodeException("Linux SLL packet is too small.");
    }

    this.packetType = PacketType.values()[buffer.getShort()];
    this.addressType = buffer.getShort();
    this.addressLength = buffer.getShort();
    this.address = new byte[8];
    buffer.get(this.address);
    int protocol = Short.toUnsignedInt(buffer.getShort());
    this.protocol = EthernetProtocol.getByValue(protocol);
  }

  @Override
  public void encode(ByteBuffer buffer) throws LayerEncodeException {
    if (buffer.remaining() < SIZE) {
      throw new LayerEncodeException("ByteBuffer is too small.");
    }

    buffer.putShort((short) this.packetType.ordinal());
    buffer.putShort((short) this.addressType);
    buffer.putShort((short) this.addressLength);
    buffer.put(this.address, 0, 8);
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

  public PacketType getPacketType() {
    return this.packetType;
  }

  public void setPacketType(PacketType packetType) {
    this.packetType = packetType;
  }

  public int getAddressType() {
    return this.addressType;
  }

  public void setAddressType(int addressType) {
    this.addressType = addressType;
  }

  public int getAddressLength() {
    return this.addressLength;
  }

  public void setAddressLength(int addressLength) {
    this.addressLength = addressLength;
  }

  public byte[] getAddress() {
    return this.address;
  }

  public void setAddress(byte[] address) {
    this.address = address;
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
    return "LinuxSLL{"
        + "packetType=" + this.packetType
        + ", addressType=" + this.addressType
        + ", addressLength=" + this.addressLength
        + ", address=" + Arrays.toString(this.address)
        + ", protocol=" + this.protocol
        + '}';
  }
}
