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

import java.util.function.Supplier;
import net.elytrium.pcap.layer.IPv4;
import net.elytrium.pcap.layer.IPv6;
import net.elytrium.pcap.layer.IPv6Destination;
import net.elytrium.pcap.layer.IPv6Fragment;
import net.elytrium.pcap.layer.IPv6HopByHop;
import net.elytrium.pcap.layer.IPv6Routing;
import net.elytrium.pcap.layer.Layer;
import net.elytrium.pcap.layer.TCP;
import net.elytrium.pcap.layer.UDP;

public enum IpProtocol {
  HOPOPT(IPv6HopByHop::new),
  ICMP,
  IGMP,
  GGP,
  IP_IN_IP(IPv4::new),
  ST,
  TCP(TCP::new),
  CBT,
  EGP,
  IGP,
  BBN_RCC_MON,
  NVP_II,
  PUP,
  ARGUS,
  EMCON,
  XNET,
  CHAOS,
  UDP(UDP::new),
  MUX,
  DCN_MEAS,
  HMP,
  PRM,
  XNS_IDP,
  TRUNK_1,
  TRUNK_2,
  LEAF_1,
  LEAF_2,
  RDP,
  IRTP,
  ISO_TP4,
  NETBLT,
  MFE_NSP,
  MERIT_INP,
  DCCP,
  TPC,
  IDPR,
  XTP,
  DDP,
  IDPR_CMTP,
  TPPP,
  IL,
  IPV6(IPv6::new),
  SDRP,
  IPV6_ROUTE(IPv6Routing::new),
  IPV6_FRAG(IPv6Fragment::new),
  IDRP,
  RSVP,
  GRE,
  MHRP,
  BNA,
  ESP,
  AH,
  I_NLSP,
  SWIPE,
  NARP,
  MOBILE,
  TLSP,
  SKIP,
  IPV6_ICMP,
  IPV6_NONXT,
  IPV6_OPTS(IPv6Destination::new),
  HOST_INTERNAL,
  CFTP,
  LOCAL_NETWORK,
  SAT_EXPAK,
  KRYPTOLAN,
  RVD,
  IPPC,
  DISTRIBUTED_FS,
  SAT_MON,
  VISA,
  IPCV,
  CPNX,
  CPHB,
  WSN,
  PVP,
  BR_SAT_MON,
  SUN_ND,
  WB_MON,
  WB_EXPAK,
  ISO_IP,
  VMTP,
  SVMTP,
  VINES,
  TTP,
  IPTM,
  NSFNET_IGP,
  DGP,
  TCF,
  EIGRP,
  OSPF,
  SPRITE_RPC,
  LARP,
  MTP,
  AX25,
  OS,
  MICP,
  SCC_SP,
  ETHERIP,
  ENCAP,
  ENC_SCHEME,
  GMTP,
  IFMP,
  PNNI,
  PIM,
  ARIS,
  SCPS,
  AN,
  IP_COMP,
  SNP,
  COMPAQ_PEER,
  IPX_IN_IP,
  VRRP,
  PGM,
  ZERO_HOP,
  L2TP,
  DDX,
  IATP,
  STP,
  SRP,
  UTI,
  SMP,
  SM,
  PTP,
  IIO_IPV4,
  FIRE,
  CRTP,
  CRUDP,
  SSCOPMCE,
  IPLT,
  SPS,
  PIPE,
  SCTP,
  FC,
  RSVP_E2E_IGN,
  MOBILITY_HEADER,
  UDP_LITE,
  MPLS_IN_IP,
  MANET,
  HIP,
  SHIM6,
  WESP,
  ROHC;

  private final Supplier<Layer> layer;

  IpProtocol(Supplier<Layer> layer) {
    this.layer = layer;
  }

  IpProtocol() {
    this.layer = null;
  }

  public Supplier<Layer> getLayer() {
    return this.layer;
  }
}
