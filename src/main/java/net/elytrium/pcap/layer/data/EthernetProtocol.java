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

package net.elytrium.pcap.layer.data;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import net.elytrium.pcap.layer.IPv4;
import net.elytrium.pcap.layer.IPv6;
import net.elytrium.pcap.layer.Layer;

public enum EthernetProtocol {
  LOOP(0x0060),
  NORTEL_DISC(0x01A2),
  PUP(0x0200),
  PUPAT(0x0201),
  CISCO_DISC(0x2000),
  TSN(0x22F0),
  ERSPAN2(0x22EB),
  IP(0x0800, IPv4::new),
  X25(0x0805),
  ARP(0x0806),
  BPQ(0x08FF),
  IEEEPUP(0x0A00),
  IEEEPUPAT(0x0A01),
  BATMAN(0x4305),
  DEC(0x6000),
  DNA_DL(0x6001),
  DNA_RC(0x6002),
  DNA_RT(0x6003),
  LAT(0x06004),
  DIAG(0x6005),
  CUST(0x6006),
  SCA(0x6007),
  TEB(0x6558),
  RARP(0x8035),
  ATALK(0x809B),
  AARP(0x80F3),
  VLAN8021Q(0x8100),
  ERSPAN(0x88BE),
  IPX(0x8137),
  IPV6(0x86DD, IPv6::new),
  PAUSE(0x8808),
  SLOW(0x8809),
  PPP(0x880B),
  WCCP(0x883E),
  MPLS_UC(0x8847),
  MPLS_MC(0x8848),
  ATMMPOA(0x884C),
  PPP_DISC(0x8863),
  PPP_SES(0x8864),
  LINK_CTL(0x886C),
  ATMFATE(0x8884),
  PAE(0x888E),
  PROFINET(0x8892),
  REALTEK(0x8899),
  AOE(0x88A2),
  ETHERCAT(0x88A4),
  VLAN8021AD(0x88A8),
  LE802_EX1(0x88B5),
  PREAUTH(0x88C7),
  TIPC(0x88CA),
  LLDP(0x88CC),
  MRP(0x88E3),
  MACSEC(0x88E5),
  BST8021AH(0x88E7),
  MVRP(0x88F5),
  IEEE1588(0x88F7),
  NCSI(0x88F8),
  PRP(0x88FB),
  CFM(0x8902),
  FCOE(0x8906),
  IBOE(0x8915),
  TDLS(0x890D),
  FIP(0x8914),
  IEEE80221(0x8917),
  HSR(0x892F),
  NSH(0x894F),
  LOOPBACK(0x9000),
  QINQ1(0x9100),
  QINQ2(0x9200),
  QINQ3(0x9300),
  EDSA(0xDADA),
  DSA_8021Q(0xDADB),
  IFE(0xED3E),
  AF_IUCV(0xFBFB);

  private static final Map<Integer, EthernetProtocol> REGISTRY = new HashMap<>();

  static {
    for (EthernetProtocol protocol : values()) {
      REGISTRY.put(protocol.getValue(), protocol);
    }
  }

  private final int value;
  private final Supplier<Layer> layer;

  EthernetProtocol(int value, Supplier<Layer> linkType) {
    this.value = value;
    this.layer = linkType;
  }

  EthernetProtocol(int value) {
    this.value = value;
    this.layer = null;
  }

  public int getValue() {
    return this.value;
  }

  public Supplier<Layer> getLayer() {
    return this.layer;
  }

  public static EthernetProtocol getByValue(int value) {
    return REGISTRY.get(value);
  }
}
