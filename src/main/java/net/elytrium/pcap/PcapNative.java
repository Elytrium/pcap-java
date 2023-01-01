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

package net.elytrium.pcap;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;

public class PcapNative {

  static {
    try {
      System.loadLibrary("pcap-native");
    } catch (UnsatisfiedLinkError e) {
      try (InputStream inputStream = PcapNative.class.getResourceAsStream("/libpcap-native.so")) {
        if (inputStream == null) {
          throw new IOException();
        }

        File directory = Files.createTempDirectory("pcap-native").toFile();
        File libraryFile = new File(directory, "libpcap-native.so");
        Files.copy(inputStream, libraryFile.toPath());
        System.load(libraryFile.getAbsolutePath());
        libraryFile.deleteOnExit();
      } catch (IOException ex) {
        ex.printStackTrace();
        throw e;
      }
    }
  }

  public static native String getErrorBuffer();

  public static native String init();

  public static native int lookupnet(String device, int[] data);

  public static native long create(String source);

  public static native String getError(long handle);

  public static native int activate(long handle);

  public static native long findAllDevs();

  public static native void freeAllDevs(long address);

  public static native long openLive(String device, int snaplen, int promisc, int timeout);

  public static native long openOffline(String fname);

  public static native long openOfflineWithTstampPrecision(String fname, int precision);

  public static native long openDead(int linktype, int snaplen);

  public static native long openDeadWithTstampPrecision(int linktype, int snaplen, int precision);

  public static native void close(long handle);

  public static native int setSnaplen(long handle, int snaplen);

  public static native int snapshot(long handle);

  public static native int setPromisc(long handle, int promisc);

  public static native int setProtocolLinux(long handle, int protocol);

  public static native int setRfmon(long handle, int rfmon);

  public static native int canSetRfmon(long handle);

  public static native int setTimeout(long handle, int ms);

  public static native int setImmediateMode(long handle, int immediateMode);

  public static native int setBufferSize(long handle, int bufferSize);

  public static native int setTstampType(long handle, int tstampType);

  public static native long listTstampTypes(long handle, int[] length);

  public static native void freeTstampTypes(long address);

  public static native String tstampTypeValToName(int tstampType);

  public static native String tstampTypeValToDescription(int tstampType);

  public static native int tstampTypeNameToVal(String name);

  public static native int setTstampPrecision(long handle, int tstampPrecision);

  public static native int getTstampPrecision(long handle);

  public static native int datalink(long handle);

  public static native int file(long handle);

  public static native int isSwapped(long handle);

  public static native int majorVersion(long handle);

  public static native int minorVersion(long handle);

  public static native long listDatalinks(long handle, int[] length);

  public static native void freeDatalinks(long address);

  public static native int loop(long handle, int count, PcapHandler handler);

  public static native int dispatch(long handle, int count, PcapHandler handler);

  public static native int next(long handle, long[] header, ByteBuffer[] buffer);

  public static native void breakLoop(long handle);

  public static native int stats(long handle, long stats);

  public static native int setFilter(long handle, long program);

  public static native int setDirection(long handle, int direction);

  public static native int getNonBlock(long handle);

  public static native int setNonBlock(long handle, int nonblock);

  public static native int inject(long handle, ByteBuffer buffer);

  public static native int sendPacket(long handle, ByteBuffer buffer);

  public static native String statusToString(int status);

  public static native String stringError(int error);

  public static native String stringErrorErrno();

  public static native int compile(long handle, long program, String str, int optimize, int netmask);

  public static native void freeCode(long handle);

  public static native int offlineFilter(long program, long header, ByteBuffer buffer);

  public static native int setDatalink(long handle, int datalink);

  public static native int datalinkNameToVal(String name);

  public static native String datalinkValToName(int datalink);

  public static native String datalinkValToDescription(int datalink);

  public static native String datalinkValToDescriptionOrDlt(int datalink);

  public static native int fileno(long handle);

  public static native long dumpOpen(long handle, String fname);

  public static native long dumpOpenAppend(long handle, String fname);

  public static native long dumpFtell(long handle);

  public static native int dumpFlush(long handle);

  public static native void dumpClose(long handle);

  public static native void dump(long handle, long header, ByteBuffer buffer);

  public static native String libVersion();
}
