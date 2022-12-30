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

package net.elytrium.pcap.layer.data;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import net.elytrium.pcap.layer.Ethernet;
import net.elytrium.pcap.layer.IPv4;
import net.elytrium.pcap.layer.IPv6;
import net.elytrium.pcap.layer.Layer;
import net.elytrium.pcap.layer.LinuxSLL;

public enum LinkType {
  NULL(0),
  ETHERNET(1, Ethernet::new),
  AX25(3),
  IEEE802_5(6),
  ARCNET_BSD(7),
  SLIP(8),
  PPP(9),
  FDDI(10),
  PPP_HDLC(50),
  PPP_ETHER(51),
  ATM_RFC1483(100),
  RAW(101),
  C_HDLC(104),
  IEEE802_11(105),
  FRELAY(107),
  LOOP(108),
  LINUX_SLL(113, LinuxSLL::new),
  LTALK(114),
  PFLOG(117),
  IEEE802_11_PRISM(119),
  IP_OVER_FC(122),
  SUNATM(123),
  IEEE802_11_RADIOTAP(127),
  ARCNET_LINUX(129),
  APPLE_IP_OVER_IEEE1394(138),
  MTP2_WITH_PHDR(139),
  MTP2(140),
  MTP3(141),
  SCCP(142),
  DOCSIS(143),
  LINUX_IRDA(144),
  USER0(147),
  USER1(148),
  USER2(149),
  USER3(150),
  USER4(151),
  USER5(152),
  USER6(153),
  USER7(154),
  USER8(155),
  USER9(156),
  USER10(157),
  USER11(158),
  USER12(159),
  USER13(160),
  USER14(161),
  USER15(162),
  IEEE802_11_AVS(163),
  BACNET_MS_TP(165),
  PPP_PPPD9(166),
  GPRS_LLC(169),
  GPF_T(170),
  GPF_F(171),
  LINUX_LAPD(177),
  MFR(182),
  BLUETOOTH_HCI_H4(187),
  USB_LINUX(189),
  PPI(192),
  IEEE802_15_4_WITHFCS(195),
  SITA(196),
  ERF(197),
  BLUETOOTH_HCI_H4_WITH_PHDR(201),
  AX25_KISS(202),
  LAPD(203),
  PPP_WITH_DIR(204),
  C_HDLC_WITH_DIR(205),
  FRELAY_WITH_DIR(206),
  LAPB_WITH_DIR(207),
  IPMB_LINUX(209),
  FLEXRAY(210),
  LIN(212),
  IEEE802_15_4_NONASK_PHY(215),
  USB_LINUX_MMAPPED(220),
  FC_2(224),
  FC_2_WITH_FRAME_DELIMS(225),
  IPNET(226),
  CAN_SCOKETCAN(227),
  IPV4(228, IPv4::new),
  IPV6(229, IPv6::new),
  IEEE802_15_4_NOFCS(230),
  DBUS(231),
  DVB_CI(235),
  MUX27010(236),
  STANAG_5066_D_PDU(237),
  NFLOG(239),
  NETANALYZER(240),
  NETANALYZER_TRANSPARENT(241),
  IPOIB(242),
  MPEG_2_TS(243),
  NG40(244),
  NFC_LLCP(245),
  INFINIBAND(247),
  SCTP(248),
  USBPCAP(249),
  RTAC_SERIAL(250),
  BLUETOOTH_LE_LL(251),
  NETLINK(253),
  BLUETOOTH_LINUX_MONITOR(254),
  BLUETOOTH_BREDR_BB(255),
  BLUETOOTH_LE_LL_WITH_PHDR(256),
  PROFIBUS_DL(257),
  PKTAP(258),
  EPON(259),
  IPMI_HPM_2(260),
  ZWAVE_R1_R2(261),
  ZWAVE_R3(262),
  WATTSTOPPER_DLM(263),
  ISO_14443(264),
  RDS(265),
  USB_DARWIN(266),
  SDLC(268),
  LORATAP(270),
  VSOCK(271),
  NORDIC_BLE(272),
  DOCSIS31_XRA31(273),
  ETHERNET_MPACKET(274),
  DISPLAYPORT_AUX(275),
  LINUX_SLL2(276),
  OPENVIZSLA(278),
  EBHSCR(279),
  VPP_DISPATCH(280),
  DSA_TAG_BRCM(281),
  DSA_TAG_BRCM_PREPEND(282),
  IEEE802_15_4_TAP(283),
  DSA_TAG_DSA(284),
  DSA_TAG_EDSA(285),
  ELEE(286),
  Z_WAVE_SERIAL(287),
  USB_2_0(288),
  ATSC_ALP(289),
  ETW(290),
  ZBOSS_NCP(292),
  USB_2_0_LOW_SPEED(293),
  USB_2_0_FULL_SPEED(294),
  USB_2_0_HIGH_SPEED(295),
  AUERSWALD_LOG(296);

  private static final Map<Integer, LinkType> REGISTRY = new HashMap<>();

  static {
    for (LinkType type : values()) {
      REGISTRY.put(type.getValue(), type);
    }
  }

  private final int value;
  private final Supplier<Layer> layer;

  LinkType(int value, Supplier<Layer> layer) {
    this.value = value;
    this.layer = layer;
  }

  LinkType(int value) {
    this.value = value;
    this.layer = null;
  }

  public int getValue() {
    return this.value;
  }

  public Supplier<Layer> getLayer() {
    return this.layer;
  }

  public static LinkType getByValue(int value) {
    return REGISTRY.get(value);
  }
}