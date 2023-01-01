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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import net.elytrium.pcap.layer.data.IpProtocol;
import net.elytrium.pcap.layer.exception.LayerDecodeException;
import net.elytrium.pcap.layer.exception.LayerEncodeException;

public class IPv6 extends IPv6Header implements IP {

  private static final int SIZE = 40;

  private int version;
  private byte trafficClass;
  private int flowLabel;
  private int payloadLength;
  private int hopLimit;
  private InetAddress srcAddress;
  private InetAddress dstAddress;

  @Override
  public void decode(ByteBuffer buffer) throws LayerDecodeException {
    if (buffer.remaining() < SIZE) {
      throw new LayerDecodeException("IPv6 header is too small.");
    }

    try {
      int versionClassFlow = buffer.getInt();
      this.version = versionClassFlow >>> 28;
      this.trafficClass = (byte) ((versionClassFlow >>> 20) & 0xFF);
      this.flowLabel = versionClassFlow & 0xFFFFF;
      this.payloadLength = Short.toUnsignedInt(buffer.getShort());
      this.nextHeader = IpProtocol.values()[Byte.toUnsignedInt(buffer.get())];
      this.hopLimit = Byte.toUnsignedInt(buffer.get());
      byte[] address = new byte[16];
      buffer.get(address);
      this.srcAddress = InetAddress.getByAddress(address);
      buffer.get(address);
      this.dstAddress = InetAddress.getByAddress(address);
    } catch (UnknownHostException e) {
      throw new LayerDecodeException(e);
    }
  }

  @Override
  public void encode(ByteBuffer buffer) throws LayerEncodeException {
    if (buffer.remaining() < SIZE) {
      throw new LayerEncodeException("ByteBuffer is too small.");
    }

    int versionClassFlow = this.version << 28;
    versionClassFlow |= this.trafficClass << 20;
    versionClassFlow |= this.flowLabel & 0xFFFFF;
    buffer.putInt(versionClassFlow);
    buffer.putShort((short) this.payloadLength);
    buffer.put((byte) this.nextHeader.ordinal());
    buffer.put((byte) this.hopLimit);
    buffer.put(this.srcAddress.getAddress());
    buffer.put(this.dstAddress.getAddress());
  }

  @Override
  public int getSize() {
    return SIZE;
  }

  @Override
  public int getVersion() {
    return this.version;
  }

  public void setVersion(int version) {
    this.version = version;
  }

  public byte getTrafficClass() {
    return this.trafficClass;
  }

  public void setTrafficClass(byte trafficClass) {
    this.trafficClass = trafficClass;
  }

  public int getFlowLabel() {
    return this.flowLabel;
  }

  public void setFlowLabel(int flowLabel) {
    this.flowLabel = flowLabel;
  }

  public int getPayloadLength() {
    return this.payloadLength;
  }

  public void setPayloadLength(int payloadLength) {
    this.payloadLength = payloadLength;
  }

  public int getHopLimit() {
    return this.hopLimit;
  }

  public void setHopLimit(int hopLimit) {
    this.hopLimit = hopLimit;
  }

  @Override
  public InetAddress getSrcAddress() {
    return this.srcAddress;
  }

  @Override
  public void setSrcAddress(InetAddress srcAddress) {
    this.srcAddress = srcAddress;
  }

  @Override
  public InetAddress getDstAddress() {
    return this.dstAddress;
  }

  @Override
  public void setDstAddress(InetAddress dstAddress) {
    this.dstAddress = dstAddress;
  }

  @Override
  public String toString() {
    return "IPv6{"
        + "version=" + this.version
        + ", trafficClass=" + this.trafficClass
        + ", flowLabel=" + this.flowLabel
        + ", payloadLength=" + this.payloadLength
        + ", hopLimit=" + this.hopLimit
        + ", srcAddress=" + this.srcAddress
        + ", dstAddress=" + this.dstAddress
        + ", nextHeader=" + this.nextHeader
        + '}';
  }
}
