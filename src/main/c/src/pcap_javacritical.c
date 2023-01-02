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

#include <jni.h>
#include <pcap/pcap.h>

JNIEXPORT jboolean JNICALL JavaCritical_net_elytrium_pcap_PcapNative_isJavaCritical() {
  return 1;
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_activate(jlong handle) {
  return pcap_activate((pcap_t *) handle);
}

JNIEXPORT void JNICALL JavaCritical_net_elytrium_pcap_PcapNative_freeAllDevs(jlong handle) {
  pcap_freealldevs((pcap_if_t *) handle);
}

JNIEXPORT jlong JNICALL JavaCritical_net_elytrium_pcap_PcapNative_openDead(jint linktype, jint snaplen) {
  return (jlong) pcap_open_dead(linktype, snaplen);
}

JNIEXPORT jlong JNICALL JavaCritical_net_elytrium_pcap_PcapNative_openDeadWithTstampPrecision(jint linktype, jint snaplen, jint precision) {
  return (jlong) pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision);
}

JNIEXPORT void JNICALL JavaCritical_net_elytrium_pcap_PcapNative_close(jlong handle) {
  pcap_close((pcap_t *) handle);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_setSnaplen(jlong handle, jint snaplen) {
  return pcap_set_snaplen((pcap_t *) handle, snaplen);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_snapshot(jlong handle) {
  return pcap_snapshot((pcap_t *) handle);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_setPromisc(jlong handle, jint promisc) {
  return pcap_set_promisc((pcap_t *) handle, promisc);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_setProtocolLinux(jlong handle, jint protocol) {
  return pcap_set_protocol_linux((pcap_t *) handle, protocol);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_setRfmon(jlong handle, jint rfmon) {
  return pcap_set_rfmon((pcap_t *) handle, rfmon);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_canSetRfmon(jlong handle) {
  return pcap_can_set_rfmon((pcap_t *) handle);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_setTimeout(jlong handle, jint ms) {
  return pcap_set_timeout((pcap_t *) handle, ms);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_setImmediateMode(jlong handle, jint immediateMode) {
  return pcap_set_immediate_mode((pcap_t *) handle, immediateMode);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_setBufferSize(jlong handle, jint bufferSize) {
  return pcap_set_buffer_size((pcap_t *) handle, bufferSize);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_setTstampType(jlong handle, jint tstampType) {
  return pcap_set_tstamp_type((pcap_t *) handle, tstampType);
}

JNIEXPORT void JNICALL JavaCritical_net_elytrium_pcap_PcapNative_freeTstampTypes(jlong address) {
  pcap_free_tstamp_types((int *) address);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_setTstampPrecision(jlong handle, jint tstampPrecision) {
  return pcap_set_tstamp_precision((pcap_t *) handle, tstampPrecision);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_getTstampPrecision(jlong handle) {
  return pcap_get_tstamp_precision((pcap_t *) handle);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_datalink(jlong handle) {
  return pcap_datalink((pcap_t *) handle);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_file(jlong handle) {
  FILE *file = pcap_file((pcap_t *) handle);
  if (file) {
    return fileno(file);
  } else {
    return 0;
  }
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_isSwapped(jlong handle) {
  return pcap_is_swapped((pcap_t *) handle);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_majorVersion(jlong handle) {
  return pcap_major_version((pcap_t *) handle);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_minorVersion(jlong handle) {
  return pcap_minor_version((pcap_t *) handle);
}

JNIEXPORT void JNICALL JavaCritical_net_elytrium_pcap_PcapNative_freeDatalinks(jlong datalinks) {
  pcap_free_datalinks((int *) datalinks);
}

JNIEXPORT void JNICALL JavaCritical_net_elytrium_pcap_PcapNative_breakLoop(jlong handle) {
  pcap_breakloop((pcap_t *) handle);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_stats(jlong handle, jlong stats) {
  return pcap_stats((pcap_t *) handle, (struct pcap_stat *) stats);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_setFilter(jlong handle, jlong program) {
  return pcap_setfilter((pcap_t *) handle, (struct bpf_program *) program);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_setDirection(jlong handle, jint direction) {
  return pcap_setdirection((pcap_t *) handle, direction);
}

JNIEXPORT void JNICALL JavaCritical_net_elytrium_pcap_PcapNative_freeCode(jlong handle) {
  pcap_freecode((struct bpf_program *) handle);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_setDatalink(jlong handle, jint datalink) {
  return pcap_set_datalink((pcap_t *) handle, datalink);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_fileno(jlong handle) {
  return pcap_fileno((pcap_t *) handle);
}

JNIEXPORT jlong JNICALL JavaCritical_net_elytrium_pcap_PcapNative_dumpFtell(jlong handle) {
  return pcap_dump_ftell((pcap_dumper_t *) handle);
}

JNIEXPORT jint JNICALL JavaCritical_net_elytrium_pcap_PcapNative_dumpFlush(jlong handle) {
  return pcap_dump_flush((pcap_dumper_t *) handle);
}

JNIEXPORT void JNICALL JavaCritical_net_elytrium_pcap_PcapNative_dumpClose(jlong handle) {
  pcap_dump_close((pcap_dumper_t *) handle);
}