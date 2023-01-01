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

package net.elytrium.pcap.handle;

import java.nio.ByteBuffer;
import net.elytrium.pcap.PcapException;
import net.elytrium.pcap.PcapNative;
import net.elytrium.pcap.data.PcapError;
import net.elytrium.pcap.data.PcapPacketHeader;

public class PcapDumper {

  private final long address;

  public PcapDumper(long address) {
    this.address = address;
  }

  public long getAddress() {
    return this.address;
  }

  public long ftell() throws PcapException {
    long position = PcapNative.dumpFtell(this.address);
    if (position < 0) {
      PcapError.throwIfNotSuccess((int) position);
    }

    return position;
  }

  public void flush() throws PcapException {
    PcapError.throwIfNotSuccess(PcapNative.dumpFlush(this.address));
  }

  public void close() {
    PcapNative.dumpClose(this.address);
  }

  public void dump(PcapPacketHeader header, ByteBuffer buffer) {
    if (!buffer.isDirect()) {
      throw new UnsupportedOperationException("Only direct buffers are supported.");
    }

    PcapNative.dump(this.address, header.getAddress(), buffer);
  }
}
