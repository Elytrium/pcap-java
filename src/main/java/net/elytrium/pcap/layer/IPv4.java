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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.function.Supplier;
import net.elytrium.pcap.layer.data.IPv4Option;
import net.elytrium.pcap.layer.data.IPv4OptionType;
import net.elytrium.pcap.layer.data.IpProtocol;
import net.elytrium.pcap.layer.exception.LayerDecodeException;
import net.elytrium.pcap.layer.exception.LayerEncodeException;

public class IPv4 implements Layer {

  private int version;
  private int ihl;
  private int tos;
  private int length;
  private int id;
  private boolean reserved;
  private boolean noFragment;
  private boolean moreFragment;
  private int fragOffset;
  private int ttl;
  private IpProtocol protocol;
  private short checksum;
  private InetAddress srcAddress;
  private InetAddress dstAddress;
  private List<IPv4Option> options;

  @Override
  public void decode(ByteBuffer buffer) throws LayerDecodeException {
    if (buffer.remaining() < 20) {
      throw new LayerDecodeException("IPv4 packet is too small.");
    }

    try {
      byte versionIhl = buffer.get();
      this.version = versionIhl >>> 4;
      this.ihl = versionIhl & 0x0F;
      this.tos = buffer.get();
      this.length = Short.toUnsignedInt(buffer.getShort());
      this.id = Short.toUnsignedInt(buffer.getShort());
      short flagsFragOffset = buffer.getShort();
      int flags = flagsFragOffset >>> 13;
      this.reserved = (flags & 0x01) != 0;
      this.noFragment = (flags & 0x02) != 0;
      this.moreFragment = (flags & 0x04) != 0;
      this.fragOffset = flagsFragOffset & 0x1FFF;
      this.ttl = Byte.toUnsignedInt(buffer.get());
      int protocolID = Byte.toUnsignedInt(buffer.get());
      this.protocol = IpProtocol.values()[protocolID];
      this.checksum = buffer.getShort();
      byte[] address = new byte[4];
      buffer.get(address);
      this.srcAddress = InetAddress.getByAddress(address);
      buffer.get(address);
      this.dstAddress = InetAddress.getByAddress(address);

      if (this.ihl > 5) {
        for (int i = 0; i < this.ihl - 5; ++i) {
          IPv4OptionType type = IPv4OptionType.getByValue(buffer.get());
          byte length = buffer.get();
          short value = buffer.getShort();
          this.options.add(new IPv4Option(type, length, value));
        }
      } else {
        this.options = null;
      }
    } catch (UnknownHostException e) {
      throw new LayerDecodeException(e);
    }
  }

  @Override
  public void encode(ByteBuffer buffer) throws LayerEncodeException {
    if (buffer.remaining() < this.getSize()) {
      throw new LayerEncodeException("ByteBuffer is too small.");
    }

    buffer.put((byte) ((this.version << 4) | (this.ihl & 0x0F)));
    buffer.put((byte) this.tos);
    buffer.putShort((short) this.length);
    buffer.putShort((short) this.id);
    int flags = this.reserved ? 0x01 : 0;
    flags |= this.noFragment ? 0x02 : 0;
    flags |= this.moreFragment ? 0x04 : 0;
    buffer.putShort((short) ((flags << 13) | (this.fragOffset & 0x1FFF)));
    buffer.put((byte) this.ttl);
    buffer.put((byte) this.protocol.ordinal());
    buffer.putShort(this.checksum);
    buffer.put(this.srcAddress.getAddress());
    buffer.put(this.dstAddress.getAddress());

    if (this.options != null) {
      for (IPv4Option option : this.options) {
        buffer.put((byte) option.getType().getValue());
        buffer.put(option.getLength());
        buffer.putShort(option.getValue());
      }
    }
  }

  @Override
  public int getSize() {
    return 20 + (this.options != null ? this.options.size() * 4 : 0);
  }

  @Override
  public Supplier<Layer> nextLayer() {
    return this.protocol != null ? this.protocol.getLayer() : null;
  }

  public int getVersion() {
    return this.version;
  }

  public void setVersion(int version) {
    this.version = version;
  }

  public int getIhl() {
    return this.ihl;
  }

  public void setIhl(int ihl) {
    this.ihl = ihl;
  }

  public int getTos() {
    return this.tos;
  }

  public void setTos(int tos) {
    this.tos = tos;
  }

  public int getLength() {
    return this.length;
  }

  public void setLength(int length) {
    this.length = length;
  }

  public int getId() {
    return this.id;
  }

  public void setId(int id) {
    this.id = id;
  }

  public boolean isReserved() {
    return this.reserved;
  }

  public void setReserved(boolean reserved) {
    this.reserved = reserved;
  }

  public boolean isNoFragment() {
    return this.noFragment;
  }

  public void setNoFragment(boolean noFragment) {
    this.noFragment = noFragment;
  }

  public boolean isMoreFragment() {
    return this.moreFragment;
  }

  public void setMoreFragment(boolean moreFragment) {
    this.moreFragment = moreFragment;
  }

  public int getFragOffset() {
    return this.fragOffset;
  }

  public void setFragOffset(int fragOffset) {
    this.fragOffset = fragOffset;
  }

  public int getTtl() {
    return this.ttl;
  }

  public void setTtl(int ttl) {
    this.ttl = ttl;
  }

  public IpProtocol getProtocol() {
    return this.protocol;
  }

  public void setProtocol(IpProtocol protocol) {
    this.protocol = protocol;
  }

  public short getChecksum() {
    return this.checksum;
  }

  public void setChecksum(short checksum) {
    this.checksum = checksum;
  }

  public InetAddress getSrcAddress() {
    return this.srcAddress;
  }

  public void setSrcAddress(InetAddress srcAddress) {
    this.srcAddress = srcAddress;
  }

  public InetAddress getDstAddress() {
    return this.dstAddress;
  }

  public void setDstAddress(InetAddress dstAddress) {
    this.dstAddress = dstAddress;
  }

  public List<IPv4Option> getOptions() {
    return this.options;
  }

  public void setOptions(List<IPv4Option> options) {
    this.options = options;
  }

  @Override
  public String toString() {
    return "IPv4{"
        + "version=" + this.version
        + ", ihl=" + this.ihl
        + ", tos=" + this.tos
        + ", length=" + this.length
        + ", id=" + this.id
        + ", reserved=" + this.reserved
        + ", noFragment=" + this.noFragment
        + ", moreFragment=" + this.moreFragment
        + ", fragOffset=" + this.fragOffset
        + ", ttl=" + this.ttl
        + ", protocol=" + this.protocol
        + ", checksum=" + this.checksum
        + ", srcAddress=" + this.srcAddress
        + ", dstAddress=" + this.dstAddress
        + ", options=" + this.options
        + '}';
  }
}
