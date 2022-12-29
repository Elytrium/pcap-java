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

package net.elytrium.pcap.handle;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import net.elytrium.pcap.PcapException;
import net.elytrium.pcap.PcapHandler;
import net.elytrium.pcap.PcapNative;
import net.elytrium.pcap.data.PcapDirection;
import net.elytrium.pcap.data.PcapError;
import net.elytrium.pcap.data.PcapPacketHeader;
import net.elytrium.pcap.data.PcapRawPacket;
import net.elytrium.pcap.data.PcapStat;
import net.elytrium.pcap.data.TstampPrecision;
import net.elytrium.pcap.data.TstampType;
import net.elytrium.pcap.layer.data.EthernetProtocol;
import net.elytrium.pcap.layer.data.LinkType;
import net.elytrium.pcap.memory.MemoryReader;
import net.elytrium.pcap.memory.MemoryUtil;
import sun.misc.Unsafe;

public class PcapHandle {

  private final long address;

  public PcapHandle(long address) {
    this.address = address;
  }

  public String getError() {
    return PcapNative.getError(this.address);
  }

  public PcapError activate() throws PcapException {
    return PcapError.throwIfError(PcapNative.activate(this.address));
  }

  public void close() {
    PcapNative.close(this.address);
  }

  public void setSnaplen(int snaplen) throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.setSnaplen(this.address, snaplen));
  }

  public int snapshot() throws PcapException {
    int length = PcapNative.snapshot(this.address);
    if (length < 0) {
      throw new PcapException(PcapError.fromCode(length));
    } else {
      return length;
    }
  }

  public void setPromisc(int promisc) throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.setPromisc(this.address, promisc));
  }

  public void setProtocolLinux(EthernetProtocol protocol) throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.setProtocolLinux(this.address, protocol.getValue()));
  }

  public void setRfmon(int rfmon) throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.setRfmon(this.address, rfmon));
  }

  public boolean canSetRfmon() throws PcapException {
    int status = PcapNative.canSetRfmon(this.address);
    if (status < 0) {
      PcapError.throwIfError(status);
    }

    return status > 0;
  }

  public void setTimeout(int ms) throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.setTimeout(this.address, ms));
  }

  public void setImmediateMode(int immediateMode) throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.setImmediateMode(this.address, immediateMode));
  }

  public void setBufferSize(int bufferSize) throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.setBufferSize(this.address, bufferSize));
  }

  public PcapError setTstampType(TstampType tstampType) throws PcapException {
    return PcapError.throwIfError(PcapNative.setTstampType(this.address, tstampType.ordinal()));
  }

  public List<TstampType> listTstampTypes() throws PcapException {
    int[] length = new int[1];
    long address = PcapNative.listTstampTypes(this.address, length);
    if (length[0] < 0) {
      PcapError.throwIfError(length[0]);
      return null;
    }

    try {
      MemoryReader reader = new MemoryReader(address);
      return IntStream.range(0, length[0])
          .mapToObj(i -> TstampType.values()[reader.readInt()])
          .collect(Collectors.toList());
    } finally {
      PcapNative.freeTstampTypes(address);
    }
  }

  public void setTstampPrecision(TstampPrecision precision) throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.setTstampPrecision(this.address, precision.ordinal()));
  }

  public TstampPrecision getTstampPrecision() {
    return TstampPrecision.values()[PcapNative.getTstampPrecision(this.address)];
  }

  public LinkType datalink() throws PcapException {
    int type = PcapNative.datalink(this.address);
    if (type < 0) {
      PcapError.throwIfNotSuccess(type);
      return null;
    } else {
      return LinkType.getByValue(type);
    }
  }

  public int file() {
    return PcapNative.file(this.address);
  }

  public boolean isSwapped() throws PcapException {
    int status = PcapNative.isSwapped(this.address);
    if (status < 0) {
      PcapError.throwIfError(status);
    }

    return status > 0;
  }

  public int majorVersion() {
    return PcapNative.majorVersion(this.address);
  }

  public int minorVersion() {
    return PcapNative.minorVersion(this.address);
  }

  public List<LinkType> listDatalinks() throws PcapException {
    int[] length = new int[1];
    long address = PcapNative.listDatalinks(this.address, length);
    if (length[0] < 0) {
      PcapError.throwIfError(length[0]);
      return null;
    }

    try {
      MemoryReader reader = new MemoryReader(address);
      return IntStream.range(0, length[0])
          .mapToObj(i -> LinkType.getByValue(reader.readInt()))
          .collect(Collectors.toList());
    } finally {
      PcapNative.freeDatalinks(address);
    }
  }

  public void loop(int count, PcapHandler handler) throws PcapException {
    Objects.requireNonNull(handler, "handler");
    PcapError.throwIfNotSuccess(PcapNative.loop(this.address, count, handler));
  }

  public void dispatch(int count, PcapHandler handler) throws PcapException {
    Objects.requireNonNull(handler, "handler");
    PcapError.throwIfNotSuccess(PcapNative.dispatch(this.address, count, handler));
  }

  public PcapRawPacket next() throws PcapException {
    long[] header = new long[1];
    ByteBuffer[] buffer = new ByteBuffer[1];
    PcapError.throwIfError(PcapNative.next(this.address, header, buffer));
    return new PcapRawPacket(PcapPacketHeader.read(header[0]), buffer[0]);
  }

  public void breakLoop() {
    PcapNative.breakLoop(this.address);
  }

  public PcapStat stats() throws PcapException {
    final int size = 6 * Integer.BYTES;

    Unsafe unsafe = MemoryUtil.getUnsafe();
    long stats = unsafe.allocateMemory(size);
    unsafe.setMemory(stats, size, (byte) 0);

    try {
      PcapError.throwIfNotSuccess(PcapNative.stats(this.address, stats));
      return PcapStat.read(stats);
    } finally {
      unsafe.freeMemory(stats);
    }
  }

  public void setFilter(BpfProgram program) throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.setFilter(this.address, program.getAddress()));
  }

  public void setDirection(PcapDirection direction) throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.setDirection(this.address, direction.ordinal()));
  }

  public boolean getNonBlock() throws PcapException {
    int status = PcapNative.getNonBlock(this.address);
    if (status < 0) {
      PcapError.throwIfNotSuccess(status);
    }

    return status > 0;
  }

  public void setNonBlock(int nonblock) throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.setNonBlock(this.address, nonblock));
  }

  public int inject(ByteBuffer buffer) throws PcapException {
    Objects.requireNonNull(buffer, "buffer");
    if (!buffer.isDirect()) {
      throw new UnsupportedOperationException("Only direct buffers are supported.");
    }

    int numBytes = PcapNative.inject(this.address, buffer);
    if (numBytes < 0) {
      PcapError.throwIfNotSuccess(numBytes);
    }

    return numBytes;
  }

  public void sendPacket(ByteBuffer buffer) throws PcapException {
    Objects.requireNonNull(buffer, "buffer");
    if (!buffer.isDirect()) {
      throw new UnsupportedOperationException("Only direct buffers are supported.");
    }

    PcapError.throwIfNotSuccess(PcapNative.sendPacket(this.address, buffer));
  }

  public BpfProgram compile(BpfProgram program, String str, int optimize, int netmask) throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.compile(this.address, program.getAddress(), str, optimize, netmask));
    return program;
  }

  public BpfProgram compile(String str, int optimize, int netmask) throws PcapException {
    return this.compile(new BpfProgram(), str, optimize, netmask);
  }

  public BpfProgram compile(BpfProgram program, String str, int optimize) throws PcapException {
    return this.compile(program, str, optimize, 0xFFFFFFFF);
  }

  public BpfProgram compile(String str, int optimize) throws PcapException {
    return this.compile(new BpfProgram(), str, optimize);
  }

  public void setDatalink(LinkType linkType) throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.setDatalink(this.address, linkType.getValue()));
  }

  public int fileno() {
    return PcapNative.fileno(this.address);
  }

  public PcapDumper dumpOpen(String fname) throws PcapException {
    long address = PcapNative.dumpOpen(this.address, fname);
    if (address == 0) {
      throw new PcapException(this.getError());
    } else {
      return new PcapDumper(address);
    }
  }

  public PcapDumper dumpOpenAppend(String fname) throws PcapException {
    long address = PcapNative.dumpOpenAppend(this.address, fname);
    if (address == 0) {
      throw new PcapException(this.getError());
    } else {
      return new PcapDumper(address);
    }
  }
}
