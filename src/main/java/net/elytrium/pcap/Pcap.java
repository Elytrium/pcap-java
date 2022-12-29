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

package net.elytrium.pcap;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;
import net.elytrium.pcap.data.PcapDevice;
import net.elytrium.pcap.data.PcapError;
import net.elytrium.pcap.data.PcapPacketHeader;
import net.elytrium.pcap.data.TstampPrecision;
import net.elytrium.pcap.data.TstampType;
import net.elytrium.pcap.handle.BpfProgram;
import net.elytrium.pcap.handle.PcapHandle;
import net.elytrium.pcap.layer.data.LinkType;

public class Pcap {

  public static void init() throws PcapException {
    String error = PcapNative.init();
    if (error != null) {
      throw new PcapException(error);
    }
  }

  public static int[] lookupnet(String device) throws PcapException {
    int[] data = new int[2];
    if (PcapNative.lookupnet(device, data) < 0) {
      throw new PcapException(PcapNative.getErrorBuffer());
    } else {
      return data;
    }
  }

  public static PcapHandle create(String source) throws PcapException {
    long address = PcapNative.create(source);
    if (address == 0) {
      throw new PcapException(PcapNative.getErrorBuffer());
    } else {
      return new PcapHandle(address);
    }
  }

  public static List<PcapDevice> findAllDevs() throws PcapException {
    long address = PcapNative.findAllDevs();
    if (address == 0) {
      throw new PcapException(PcapNative.getErrorBuffer());
    }

    List<PcapDevice> devices = PcapDevice.read(address);
    PcapNative.freeAllDevs(address);
    return devices;
  }

  public static PcapHandle openLive(String device, int snaplen, int promisc, int timeout) throws PcapException {
    long address = PcapNative.openLive(device, snaplen, promisc, timeout);
    if (address == 0) {
      throw new PcapException(PcapNative.getErrorBuffer());
    } else {
      return new PcapHandle(address);
    }
  }

  public static PcapHandle openOffline(String fname) throws PcapException {
    long address = PcapNative.openOffline(fname);
    if (address == 0) {
      throw new PcapException(PcapNative.getErrorBuffer());
    } else {
      return new PcapHandle(address);
    }
  }

  public static PcapHandle openOffline(String fname, TstampPrecision precision) throws PcapException {
    long address = PcapNative.openOfflineWithTstampPrecision(fname, precision.ordinal());
    if (address == 0) {
      throw new PcapException(PcapNative.getErrorBuffer());
    } else {
      return new PcapHandle(address);
    }
  }

  public static PcapHandle openDead(LinkType linktype, int snaplen) throws PcapException {
    long address = PcapNative.openDead(linktype.getValue(), snaplen);
    if (address == 0) {
      throw new PcapException();
    } else {
      return new PcapHandle(address);
    }
  }

  public static PcapHandle openDead(LinkType linktype, int snaplen, TstampPrecision precision) throws PcapException {
    long address = PcapNative.openDeadWithTstampPrecision(linktype.getValue(), snaplen, precision.ordinal());
    if (address == 0) {
      throw new PcapException();
    } else {
      return new PcapHandle(address);
    }
  }

  public static String getTstampTypeName(TstampType type) {
    return PcapNative.tstampTypeValToName(type.ordinal());
  }

  public static String getTstampTypeDescription(TstampType type) {
    return PcapNative.tstampTypeValToDescription(type.ordinal());
  }

  public static TstampType getTstampType(String name) throws PcapException {
    int value = PcapNative.tstampTypeNameToVal(name);
    if (value < 0) {
      PcapError.throwIfNotSuccess(value);
      return null;
    } else {
      return TstampType.values()[value];
    }
  }

  public static String statusToString(PcapError status) {
    return PcapNative.statusToString(status.getValue());
  }

  public static String stringError(int errno) {
    return PcapNative.stringError(errno);
  }

  public static String stringError() {
    return PcapNative.stringErrorErrno();
  }

  public static boolean offlineFilter(BpfProgram program, PcapPacketHeader header, ByteBuffer buffer) {
    Objects.requireNonNull(buffer, "buffer");
    return PcapNative.offlineFilter(program.getAddress(), header.getAddress(), buffer) > 0;
  }

  public static LinkType getDatalink(String name) {
    return LinkType.getByValue(PcapNative.datalinkNameToVal(name));
  }

  public static String getDatalinkName(LinkType linkType) {
    return PcapNative.datalinkValToName(linkType.getValue());
  }

  public static String getDatalinkDescription(LinkType linkType) {
    return PcapNative.datalinkValToDescription(linkType.getValue());
  }

  public static String getDatalinkDescriptionOrDlt(LinkType linkType) {
    return PcapNative.datalinkValToDescriptionOrDlt(linkType.getValue());
  }

  public static String libVersion() {
    return PcapNative.libVersion();
  }
}
