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

import net.elytrium.pcap.PcapNative;
import net.elytrium.pcap.memory.MemoryUtil;
import sun.misc.Unsafe;

public class BpfProgram {

  private static final int SIZE = Integer.BYTES + Unsafe.ADDRESS_SIZE;

  private final long address;

  public BpfProgram(long address) {
    this.address = address;
  }

  public BpfProgram() {
    Unsafe unsafe = MemoryUtil.getUnsafe();
    this.address = unsafe.allocateMemory(SIZE);
    unsafe.setMemory(this.address, SIZE, (byte) 0);
  }

  public long getAddress() {
    return this.address;
  }

  public void freeCode() {
    PcapNative.freeCode(this.address);
  }

  public void freeMemory() {
    MemoryUtil.getUnsafe().freeMemory(this.address);
  }

  public void free() {
    this.freeCode();
    this.freeMemory();
  }
}
