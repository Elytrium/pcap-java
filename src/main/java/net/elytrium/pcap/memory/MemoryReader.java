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

package net.elytrium.pcap.memory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import sun.misc.Unsafe;

public class MemoryReader {

  private long address;

  public MemoryReader(long address) {
    this.address = address;
  }

  public void skipBytes(int n) {
    this.address += n;
  }

  public byte readByte() {
    try {
      return MemoryUtil.getUnsafe().getByte(this.address);
    } finally {
      this.address += Byte.BYTES;
    }
  }

  public short readShort() {
    try {
      return MemoryUtil.getUnsafe().getShort(this.address);
    } finally {
      this.address += Short.BYTES;
    }
  }

  public int readInt() {
    try {
      return MemoryUtil.getUnsafe().getInt(this.address);
    } finally {
      this.address += Integer.BYTES;
    }
  }

  public long readLong() {
    try {
      return MemoryUtil.getUnsafe().getLong(this.address);
    } finally {
      this.address += Long.BYTES;
    }
  }

  public long readAddress() {
    try {
      return MemoryUtil.getUnsafe().getAddress(this.address);
    } finally {
      this.address += Unsafe.ADDRESS_SIZE;
    }
  }

  public byte[] readBytes(byte[] array) {
    for (int i = 0; i < array.length; i++) {
      array[i] = this.readByte();
    }

    return array;
  }

  public byte[] readBytes(int length) {
    return this.readBytes(new byte[length]);
  }

  public InetSocketAddress readSockaddr() {
    long address = this.readAddress();
    if (address == 0) {
      return null;
    }

    MemoryReader reader = new MemoryReader(address);
    short family = reader.readShort();
    short port;
    byte[] addr;

    if (family == 2) {
      port = reader.readShort();
      addr = reader.readBytes(4);
    } else if (family == 10) {
      port = reader.readShort();
      reader.skipBytes(4);
      addr = reader.readBytes(16);
    } else {
      return null;
    }

    try {
      return new InetSocketAddress(InetAddress.getByAddress(addr), port);
    } catch (UnknownHostException e) {
      return null;
    }
  }

  public String readString() {
    long address = this.readAddress();
    if (address == 0) {
      return null;
    }

    MemoryReader reader = new MemoryReader(address);
    try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
      byte b;
      while ((b = reader.readByte()) != 0) {
        outputStream.write(b);
      }

      return outputStream.toString("UTF-8");
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  public long getAddress() {
    return this.address;
  }

  public void setAddress(long address) {
    this.address = address;
  }
}
