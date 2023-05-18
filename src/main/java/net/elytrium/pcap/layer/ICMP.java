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
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import net.elytrium.pcap.layer.exception.LayerDecodeException;
import net.elytrium.pcap.layer.exception.LayerEncodeException;

public class ICMP implements Layer {

  public enum Type {
    ECHO_REPLY(0, EchoReply.class),
    DESTINATION_UNREACHABLE(3, DestinationUnreachable.class),
    SOURCE_QUENCH(4, SourceQuench.class),
    REDIRECT_MESSAGE(5, RedirectMessage.class),
    ECHO_REQUEST(8, EchoRequest.class),
    ROUTER_ADVERTISEMENT(9, RouterAdvertisement.class),
    ROUTER_SOLICITATION(10, RouterSolicitation.class),
    TIME_EXCEEDED(11, TimeExceeded.class),
    BAD_IP_HEADER(12, BadIPHeader.class),
    TIMESTAMP(13, Timestamp.class),
    TIMESTAMP_REPLY(14, TimestampReply.class),
    INFORMATION_REQUEST(15, InformationRequest.class),
    INFORMATION_REPLY(16, InformationReply.class),
    ADDRESS_MASK_REQUEST(17, AddressMaskRequest.class),
    ADDRESS_MASK_REPLY(18, AddressMaskReply.class),
    TRACEROUTE(30, Traceroute.class),
    EXTENDED_ECHO_REQUEST(42, ExtendedEchoRequest.class),
    EXTENDED_ECHO_RESPONSE(43, ExtendedEchoResponse.class);

    private static final Map<Integer, Type> VALUE_REGISTRY = new HashMap<>();
    private static final Map<Class<? extends Enum<?>>, Type> ENUM_REGISTRY = new HashMap<>();

    static {
      for (Type type : values()) {
        VALUE_REGISTRY.put(type.getValue(), type);
        ENUM_REGISTRY.put(type.getEnumClass(), type);
      }
    }

    private final int value;
    private final Class<? extends Enum<?>> enumClass;

    Type(int value, Class<? extends Enum<?>> enumClass) {
      this.value = value;
      this.enumClass = enumClass;
    }

    public int getValue() {
      return this.value;
    }

    public Class<? extends Enum<?>> getEnumClass() {
      return this.enumClass;
    }

    public static Type getByValue(int value) {
      return VALUE_REGISTRY.get(value);
    }

    public static Type getByEnum(@SuppressWarnings("rawtypes") Class<? extends Enum> cls) {
      return ENUM_REGISTRY.get(cls);
    }

    public static Type getByEnum(Enum<?> value) {
      return value == null ? null : getByEnum(value.getClass());
    }
  }

  public enum EchoReply {
    ECHO_REPLY
  }

  public enum DestinationUnreachable {
    DESTINATION_NETWORK_UNREACHABLE,
    DESTINATION_HOST_UNREACHABLE,
    DESTINATION_PROTOCOL_UNREACHABLE,
    DESTINATION_PORT_UNREACHABLE,
    FRAGMENTATION_REQUIRED,
    SOURCE_ROUTE_FAILED,
    DESTINATION_NETWORK_UNKNOWN,
    DESTINATION_HOST_UNKNOWN,
    SOURCE_HOST_ISOLATED,
    NETWORK_ADMINISTRATIVELY_PROHIBITED,
    HOST_ADMINISTRATIVELY_PROHIBITED,
    NETWORK_UNREACHABLE_TOS,
    HOST_UNREACHABLE_TOS,
    COMMUNICATION_ADMINISTRATIVELY_PROHIBITED,
    HOST_PRECEDENCE_VIOLATION,
    PRECEDENCE_CUTOFF_IN_EFFECT
  }

  public enum SourceQuench {
    SOURCE_QUENCH
  }

  public enum RedirectMessage {
    REDIRECT_DATAGRAM_NETWORK,
    REDIRECT_DATAGRAM_HOST,
    REDIRECT_DATAGRAM_NETWORK_TOS,
    REDIRECT_DATAGRAM_HOST_TOS
  }

  public enum EchoRequest {
    ECHO_REQUEST
  }

  public enum RouterAdvertisement {
    ROUTER_ADVERTISEMENT
  }

  public enum RouterSolicitation {
    ROUTER_SOLICITATION
  }

  public enum TimeExceeded {
    TTL_EXPIRED,
    FRAGMENT_REASSEMBLY
  }

  public enum BadIPHeader {
    MISSING_REQUIRED_OPTION,
    BAD_LENGTH
  }

  public enum Timestamp {
    TIMESTAMP
  }

  public enum TimestampReply {
    TIMESTAMP_REPLY
  }

  public enum InformationRequest {
    INFORMATION_REQUEST
  }

  public enum InformationReply {
    INFORMATION_REPLY
  }

  public enum AddressMaskRequest {
    ADDRESS_MASK_REQUEST
  }

  public enum AddressMaskReply {
    ADDRESS_MASK_REPLY
  }

  public enum Traceroute {
    TRACEROUTE
  }

  public enum ExtendedEchoRequest {
    EXTENDED_ECHO_REQUEST
  }

  public enum ExtendedEchoResponse {
    NO_ERROR,
    MALFORMED_QUERY,
    NO_SUCH_INTERFACE,
    NO_SUCH_TABLE_ENTRY,
    MULTIPLE_INTERFACES_SATISFY_QUERY
  }

  private static final int SIZE = 8;

  private Type type;
  private int code;
  private short checksum;
  private int data;

  @Override
  public void decode(ByteBuffer buffer) throws LayerDecodeException {
    if (buffer.remaining() < SIZE) {
      throw new LayerDecodeException("ICMP header is too small.");
    }

    this.type = Type.getByValue(Byte.toUnsignedInt(buffer.get()));
    this.code = Byte.toUnsignedInt(buffer.get());
    this.checksum = buffer.getShort();
    this.data = buffer.getInt();
  }

  @Override
  public void encode(ByteBuffer buffer) throws LayerEncodeException {
    if (buffer.remaining() < SIZE) {
      throw new LayerEncodeException("ByteBuffer is too small.");
    }

    buffer.put((byte) this.type.getValue());
    buffer.put((byte) this.code);
    buffer.putShort(this.checksum);
    buffer.putInt(this.data);
  }

  @Override
  public int getSize() {
    return SIZE;
  }

  @Override
  public Supplier<Layer> nextLayer() {
    return null;
  }

  public Type getType() {
    return this.type;
  }

  public void setType(Type type) {
    this.type = type;
  }

  public int getCodeId() {
    return this.code;
  }

  public void setCodeId(int code) {
    this.code = code;
  }

  public Enum<?> getCode() {
    if (this.type == null) {
      return null;
    }

    Enum<?>[] values = this.type.getEnumClass().getEnumConstants();
    if (this.code >= values.length) {
      return null;
    }

    return values[this.code];
  }

  public void setCode(Enum<?> code) {
    this.code = code.ordinal();
  }

  public void setTypeAndCode(Enum<?> code) {
    this.type = Type.getByEnum(code);
    this.code = code.ordinal();
  }

  public short getChecksum() {
    return this.checksum;
  }

  public void setChecksum(short checksum) {
    this.checksum = checksum;
  }

  public int getData() {
    return this.data;
  }

  public void setData(int data) {
    this.data = data;
  }

  @Override
  public String toString() {
    return "ICMP{"
        + "type=" + this.type
        + ", code=" + this.code
        + ", checksum=" + this.checksum
        + ", data=" + this.data
        + '}';
  }
}
