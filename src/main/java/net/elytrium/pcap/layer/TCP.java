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
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import net.elytrium.pcap.layer.data.TCPOption;
import net.elytrium.pcap.layer.data.TCPOptionType;
import net.elytrium.pcap.layer.exception.LayerDecodeException;
import net.elytrium.pcap.layer.exception.LayerEncodeException;

public class TCP implements Layer {

  private int srcPort;
  private int dstPort;
  private int sequence;
  private int ackSn;
  private byte dataOffset;
  private boolean fin;
  private boolean syn;
  private boolean rst;
  private boolean psh;
  private boolean ack;
  private boolean urg;
  private boolean ece;
  private boolean cwr;
  private boolean ns;
  private int windowSize;
  private short checksum;
  private int urgPtr;
  private List<TCPOption> options;

  @Override
  public void decode(ByteBuffer buffer) throws LayerDecodeException {
    if (buffer.remaining() < 20) {
      throw new LayerDecodeException("TCP packet is too small.");
    }

    this.srcPort = Short.toUnsignedInt(buffer.getShort());
    this.dstPort = Short.toUnsignedInt(buffer.getShort());
    this.sequence = buffer.getInt();
    this.ackSn = buffer.getInt();
    short offsetFlags = buffer.getShort();
    this.dataOffset = (byte) ((offsetFlags >>> 12) & 0xF);
    this.fin = (offsetFlags & 0x01) != 0;
    this.syn = (offsetFlags & 0x02) != 0;
    this.rst = (offsetFlags & 0x04) != 0;
    this.psh = (offsetFlags & 0x08) != 0;
    this.ack = (offsetFlags & 0x10) != 0;
    this.urg = (offsetFlags & 0x20) != 0;
    this.ece = (offsetFlags & 0x40) != 0;
    this.cwr = (offsetFlags & 0x80) != 0;
    this.ns = (offsetFlags & 0x100) != 0;
    this.windowSize = Short.toUnsignedInt(buffer.getShort());
    this.checksum = buffer.getShort();
    this.urgPtr = Short.toUnsignedInt(buffer.getShort());

    if (this.dataOffset > 5) {
      this.options = new ArrayList<>();
      int position = buffer.position();
      int optionsSize = (this.dataOffset - 5) * 4;
      while (buffer.position() - position < optionsSize) {
        TCPOptionType type = TCPOptionType.getByValue(buffer.get());
        byte[] value = null;
        if (type != null && type.hasData()) {
          int length = Byte.toUnsignedInt(buffer.get()) - 2;
          if (length > 0) {
            value = new byte[length];
            buffer.get(value);
          }
        }

        this.options.add(new TCPOption(type, value));
      }
    } else {
      this.options = null;
    }
  }

  @Override
  public void encode(ByteBuffer buffer) throws LayerEncodeException {
    int size = this.getSize();
    if (buffer.remaining() < size) {
      throw new LayerEncodeException("ByteBuffer is too small.");
    }

    int position = buffer.position() + size;
    buffer.putShort((short) this.srcPort);
    buffer.putShort((short) this.dstPort);
    buffer.putInt(this.sequence);
    buffer.putInt(this.ackSn);
    short offsetFlags = (short) ((this.dataOffset & 0xF) << 12);
    offsetFlags |= this.fin ? 0x01 : 0;
    offsetFlags |= this.syn ? 0x02 : 0;
    offsetFlags |= this.rst ? 0x04 : 0;
    offsetFlags |= this.psh ? 0x08 : 0;
    offsetFlags |= this.ack ? 0x10 : 0;
    offsetFlags |= this.urg ? 0x20 : 0;
    offsetFlags |= this.ece ? 0x40 : 0;
    offsetFlags |= this.cwr ? 0x80 : 0;
    offsetFlags |= this.ns ? 0x100 : 0;
    buffer.putShort(offsetFlags);
    buffer.putShort((short) this.windowSize);
    buffer.putShort(this.checksum);
    buffer.putShort((short) this.urgPtr);

    if (this.options != null) {
      this.options.forEach(option -> {
        TCPOptionType type = option.getType();
        buffer.put((byte) type.getValue());
        if (type.hasData()) {
          byte[] value = option.getValue();
          int length = 2 + (value != null ? value.length : 0);
          buffer.put((byte) length);
          if (value != null) {
            buffer.put(value);
          }
        }
      });

      buffer.put(new byte[position - buffer.position()]);
    }
  }

  @Override
  public int getSize() {
    int optionsSize = this.options != null
        ? this.options.stream()
        .mapToInt(option -> {
          int size = 1;
          if (option.getType().hasData()) {
            byte[] value = option.getValue();
            size += 1 + (value != null ? value.length : 0);
          }

          return size;
        }).sum()
        : 0;
    return 20 + (optionsSize + 3 & ~0x3);
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

  public int getSequence() {
    return this.sequence;
  }

  public void setSequence(int sequence) {
    this.sequence = sequence;
  }

  public int getAckSn() {
    return this.ackSn;
  }

  public void setAckSn(int ackSn) {
    this.ackSn = ackSn;
  }

  public byte getDataOffset() {
    return this.dataOffset;
  }

  public void setDataOffset(byte dataOffset) {
    this.dataOffset = dataOffset;
  }

  public boolean isFin() {
    return this.fin;
  }

  public void setFin(boolean fin) {
    this.fin = fin;
  }

  public boolean isSyn() {
    return this.syn;
  }

  public void setSyn(boolean syn) {
    this.syn = syn;
  }

  public boolean isRst() {
    return this.rst;
  }

  public void setRst(boolean rst) {
    this.rst = rst;
  }

  public boolean isPsh() {
    return this.psh;
  }

  public void setPsh(boolean psh) {
    this.psh = psh;
  }

  public boolean isAck() {
    return this.ack;
  }

  public void setAck(boolean ack) {
    this.ack = ack;
  }

  public boolean isUrg() {
    return this.urg;
  }

  public void setUrg(boolean urg) {
    this.urg = urg;
  }

  public boolean isEce() {
    return this.ece;
  }

  public void setEce(boolean ece) {
    this.ece = ece;
  }

  public boolean isCwr() {
    return this.cwr;
  }

  public void setCwr(boolean cwr) {
    this.cwr = cwr;
  }

  public boolean isNs() {
    return this.ns;
  }

  public void setNs(boolean ns) {
    this.ns = ns;
  }

  public int getWindowSize() {
    return this.windowSize;
  }

  public void setWindowSize(int windowSize) {
    this.windowSize = windowSize;
  }

  public short getChecksum() {
    return this.checksum;
  }

  public void setChecksum(short checksum) {
    this.checksum = checksum;
  }

  public int getUrgPtr() {
    return this.urgPtr;
  }

  public void setUrgPtr(int urgPtr) {
    this.urgPtr = urgPtr;
  }

  public List<TCPOption> getOptions() {
    return this.options;
  }

  public void setOptions(List<TCPOption> options) {
    this.options = options;
  }

  @Override
  public String toString() {
    return "TCP{"
        + "srcPort=" + this.srcPort
        + ", dstPort=" + this.dstPort
        + ", sequence=" + this.sequence
        + ", ackSn=" + this.ackSn
        + ", dataOffset=" + this.dataOffset
        + ", fin=" + this.fin
        + ", syn=" + this.syn
        + ", rst=" + this.rst
        + ", psh=" + this.psh
        + ", ack=" + this.ack
        + ", urg=" + this.urg
        + ", ece=" + this.ece
        + ", cwr=" + this.cwr
        + ", ns=" + this.ns
        + ", windowSize=" + this.windowSize
        + ", checksum=" + this.checksum
        + ", urgPtr=" + this.urgPtr
        + ", options=" + this.options
        + '}';
  }
}
