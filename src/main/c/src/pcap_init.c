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

#include <jni/net_elytrium_pcap_PcapNative.h>
#include <pcap/pcap.h>

JNIEXPORT jstring JNICALL Java_net_elytrium_pcap_PcapNative_init(JNIEnv *env, jclass class) {
  char errbuf[PCAP_ERRBUF_SIZE];
  if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf)) {
    return (*env)->NewStringUTF(env, errbuf);
  } else {
    return NULL;
  }
}