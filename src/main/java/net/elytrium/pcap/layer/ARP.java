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

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import net.elytrium.pcap.layer.data.EthernetProtocol;
import net.elytrium.pcap.layer.exception.LayerDecodeException;
import net.elytrium.pcap.layer.exception.LayerEncodeException;

public class ARP implements Layer {

  public enum HardwareType {
    ETHERNET(1),
    EXPERIMENTAL_ETHERNET(2),
    AMATEUR_RADIO_AX_25(3),
    PROTEON_PRONET_TOKEN_RING(4),
    CHAOS(5),
    IEEE802_NETWORKS(6),
    ARCNET(7),
    HYPERCHANNEL(8),
    LANSTAR(9),
    AUTONET_SHORT_ADDRESS(10),
    LOCALTALK(11),
    LOCALNET(12),
    ULTRA_LINK(13),
    SMDS(14),
    FRAME_RELAY(15),
    HDLC(17),
    FIBRE_CHANNEL(18),
    ATM(19),
    SERIAL_LINE(20),
    MIL_STD_188_220(22),
    METRICOM(23),
    IEEE1394_1995(24),
    MAPOS(25),
    TWINAXIAL(26),
    EUI_64(27),
    HIPARP(28),
    IP_ARP_OVER_ISO_7816_3(29),
    ARPSEC(30),
    IPSEC_TUNNEL(31),
    INFINIBAND(32),
    TIA_102_PROJECT_25_CAI(33),
    WIEGAND_INTERFACE(34),
    PURE_IP(35),
    HW_EXP1(36),
    HFI(37),
    UNIFIED_BUS(38),
    HW_EXP2(256),
    AETHERNET(257);

    private static final Map<Integer, HardwareType> REGISTRY = new HashMap<>();

    static {
      for (HardwareType type : values()) {
        REGISTRY.put(type.getValue(), type);
      }
    }

    final int value;

    HardwareType(int value) {
      this.value = value;
    }

    public int getValue() {
      return this.value;
    }

    public static HardwareType getByValue(int value) {
      return REGISTRY.get(value);
    }
  }

  public enum Operation {
    REQUEST(1),
    REPLY(2),
    REQUEST_REVERSE(3),
    REPLY_REVERSE(4),
    DRARP_REQUEST(5),
    DRARP_REPLY(6),
    DRARP_ERROR(7),
    INARP_REQUEST(8),
    INARP_REPLY(9),
    ARP_NAK(10),
    MARS_REQUEST(11),
    MARS_MULTI(12),
    MARS_MSERV(13),
    MARS_JOIN(14),
    MARS_LEAVE(15),
    MARS_NAK(16),
    MARS_UNSERV(17),
    MARS_SJOIN(18),
    MARS_SLEAVE(19),
    MARS_GROUPLIST_REQUEST(20),
    MARS_GROUPLIST_REPLY(21),
    MARS_REDIRECT_MAP(22),
    MAPOS_UNARP(23),
    OP_EXP1(24),
    OP_EXP2(25);

    private static final Map<Integer, Operation> REGISTRY = new HashMap<>();

    static {
      for (Operation operation : values()) {
        REGISTRY.put(operation.getValue(), operation);
      }
    }

    final int value;

    Operation(int value) {
      this.value = value;
    }

    public int getValue() {
      return this.value;
    }

    public static Operation getByValue(int value) {
      return REGISTRY.get(value);
    }
  }

  private HardwareType hardwareType;
  private EthernetProtocol protocolType;
  private int hardwareLength;
  private int protocolLength;
  private Operation operation;
  private byte[] senderHardwareAddress;
  private byte[] senderProtocolAddress;
  private byte[] targetHardwareAddress;
  private byte[] targetProtocolAddress;

  @Override
  public void decode(ByteBuffer buffer) throws LayerDecodeException {
    if (buffer.remaining() < 8) {
      throw new LayerDecodeException("ARP packet is too small.");
    }

    this.hardwareType = HardwareType.getByValue(Short.toUnsignedInt(buffer.getShort()));
    this.protocolType = EthernetProtocol.getByValue(Short.toUnsignedInt(buffer.getShort()));
    this.hardwareLength = Byte.toUnsignedInt(buffer.get());
    this.protocolLength = Byte.toUnsignedInt(buffer.get());
    this.operation = Operation.getByValue(Short.toUnsignedInt(buffer.getShort()));
    this.senderHardwareAddress = new byte[this.hardwareLength];
    buffer.get(this.senderHardwareAddress);
    this.senderProtocolAddress = new byte[this.protocolLength];
    buffer.get(this.protocolLength);
    this.targetHardwareAddress = new byte[this.hardwareLength];
    buffer.get(this.targetHardwareAddress);
    this.targetProtocolAddress = new byte[this.protocolLength];
    buffer.get(this.targetProtocolAddress);
  }

  @Override
  public void encode(ByteBuffer buffer) throws LayerEncodeException {
    if (buffer.remaining() < this.getSize()) {
      throw new LayerEncodeException("ByteBuffer is too small.");
    }

    buffer.putShort((short) this.hardwareType.getValue());
    buffer.putShort((short) this.protocolType.getValue());
    buffer.put((byte) this.hardwareLength);
    buffer.put((byte) this.protocolLength);
    buffer.putShort((short) this.operation.getValue());
    buffer.put(this.senderHardwareAddress);
    buffer.put(this.senderProtocolAddress);
    buffer.put(this.targetHardwareAddress);
    buffer.put(this.targetProtocolAddress);
  }

  @Override
  public int getSize() {
    return 8 + this.hardwareLength * 2 + this.protocolLength * 2;
  }

  @Override
  public Supplier<Layer> nextLayer() {
    return null;
  }

  public HardwareType getHardwareType() {
    return this.hardwareType;
  }

  public void setHardwareType(HardwareType hardwareType) {
    this.hardwareType = hardwareType;
  }

  public EthernetProtocol getProtocolType() {
    return this.protocolType;
  }

  public void setProtocolType(EthernetProtocol protocolType) {
    this.protocolType = protocolType;
  }

  public int getHardwareLength() {
    return this.hardwareLength;
  }

  public void setHardwareLength(int hardwareLength) {
    this.hardwareLength = hardwareLength;
  }

  public int getProtocolLength() {
    return this.protocolLength;
  }

  public void setProtocolLength(int protocolLength) {
    this.protocolLength = protocolLength;
  }

  public Operation getOperation() {
    return this.operation;
  }

  public void setOperation(Operation operation) {
    this.operation = operation;
  }

  public byte[] getSenderHardwareAddress() {
    return this.senderHardwareAddress;
  }

  public void setSenderHardwareAddress(byte[] senderHardwareAddress) {
    this.senderHardwareAddress = senderHardwareAddress;
  }

  public byte[] getSenderProtocolAddress() {
    return this.senderProtocolAddress;
  }

  public void setSenderProtocolAddress(byte[] senderProtocolAddress) {
    this.senderProtocolAddress = senderProtocolAddress;
  }

  public byte[] getTargetHardwareAddress() {
    return this.targetHardwareAddress;
  }

  public void setTargetHardwareAddress(byte[] targetHardwareAddress) {
    this.targetHardwareAddress = targetHardwareAddress;
  }

  public byte[] getTargetProtocolAddress() {
    return this.targetProtocolAddress;
  }

  public void setTargetProtocolAddress(byte[] targetProtocolAddress) {
    this.targetProtocolAddress = targetProtocolAddress;
  }

  @Override
  public String toString() {
    return "ARP{"
        + "hardwareType=" + this.hardwareType
        + ", protocolType=" + this.protocolType
        + ", hardwareLength=" + this.hardwareLength
        + ", protocolLength=" + this.protocolLength
        + ", operation=" + this.operation
        + ", senderHardwareAddress=" + Arrays.toString(this.senderHardwareAddress)
        + ", senderProtocolAddress=" + Arrays.toString(this.senderProtocolAddress)
        + ", targetHardwareAddress=" + Arrays.toString(this.targetHardwareAddress)
        + ", targetProtocolAddress=" + Arrays.toString(this.targetProtocolAddress)
        + '}';
  }
}
