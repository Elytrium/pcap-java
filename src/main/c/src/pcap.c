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

#include <errno.h>
#include <jni/net_elytrium_pcap_PcapNative.h>
#include <pcap/pcap.h>
#include <threads.h>

typedef struct {
  JNIEnv *env;
  jobject handler;
} jni_callback_t;

thread_local char errbuf[PCAP_ERRBUF_SIZE];

JNIEXPORT jstring JNICALL Java_net_elytrium_pcap_PcapNative_getErrorBuffer(JNIEnv *env, jclass class) {
  return (*env)->NewStringUTF(env, errbuf);
}

JNIEXPORT jstring JNICALL Java_net_elytrium_pcap_PcapNative_init(JNIEnv *env, jclass class) {
  if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf)) {
    return (*env)->NewStringUTF(env, errbuf);
  } else {
    return NULL;
  }
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_lookupnet(JNIEnv *env, jclass class, jstring jdevice, jintArray jdata) {
  uint32_t net;
  uint32_t mask;
  const char *device = (*env)->GetStringUTFChars(env, jdevice, NULL);
  jint error = pcap_lookupnet(device, &net, &mask, errbuf);
  (*env)->ReleaseStringUTFChars(env, jdevice, device);
  (*env)->SetIntArrayRegion(env, jdata, 0, 1, (jint *) &net);
  (*env)->SetIntArrayRegion(env, jdata, 1, 1, (jint *) &mask);
  return error;
}

JNIEXPORT jlong JNICALL Java_net_elytrium_pcap_PcapNative_create(JNIEnv *env, jclass class, jstring jsource) {
  const char *source = (*env)->GetStringUTFChars(env, jsource, NULL);
  pcap_t *handle = pcap_create(source, errbuf);
  (*env)->ReleaseStringUTFChars(env, jsource, source);
  return (jlong) handle;
}

JNIEXPORT jstring JNICALL Java_net_elytrium_pcap_PcapNative_getError(JNIEnv *env, jclass class, jlong handle) {
  return (*env)->NewStringUTF(env, pcap_geterr((pcap_t *) handle));
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_activate(JNIEnv *env, jclass class, jlong handle) {
  return pcap_activate((pcap_t *) handle);
}

JNIEXPORT jlong JNICALL Java_net_elytrium_pcap_PcapNative_findAllDevs(JNIEnv *env, jclass class) {
  pcap_if_t *device;
  if (pcap_findalldevs(&device, errbuf)) {
    return 0;
  } else {
    return (jlong) device;
  }
}

JNIEXPORT void JNICALL Java_net_elytrium_pcap_PcapNative_freeAllDevs(JNIEnv *env, jclass class, jlong handle) {
  pcap_freealldevs((pcap_if_t *) handle);
}

JNIEXPORT jlong JNICALL Java_net_elytrium_pcap_PcapNative_openLive(JNIEnv *env, jclass class, jstring jdevice, jint snaplen, jint promisc, jint timeout) {
  const char *device = (*env)->GetStringUTFChars(env, jdevice, NULL);
  pcap_t *handle = pcap_open_live(device, snaplen, promisc, timeout, errbuf);
  (*env)->ReleaseStringUTFChars(env, jdevice, device);
  return (jlong) handle;
}

JNIEXPORT jlong JNICALL Java_net_elytrium_pcap_PcapNative_openOffline(JNIEnv *env, jclass class, jstring jfname) {
  const char *fname = (*env)->GetStringUTFChars(env, jfname, NULL);
  pcap_t *handle = pcap_open_offline(fname, errbuf);
  (*env)->ReleaseStringUTFChars(env, jfname, fname);
  return (jlong) handle;
}

JNIEXPORT jlong JNICALL Java_net_elytrium_pcap_PcapNative_openOfflineWithTstampPrecision(JNIEnv *env, jclass class, jstring jfname, jint precision) {
  const char *fname = (*env)->GetStringUTFChars(env, jfname, NULL);
  pcap_t *handle = pcap_open_offline_with_tstamp_precision(fname, precision, errbuf);
  (*env)->ReleaseStringUTFChars(env, jfname, fname);
  return (jlong) handle;
}

JNIEXPORT jlong JNICALL Java_net_elytrium_pcap_PcapNative_openDead(JNIEnv *env, jclass class, jint linktype, jint snaplen) {
  return (jlong) pcap_open_dead(linktype, snaplen);
}

JNIEXPORT jlong JNICALL Java_net_elytrium_pcap_PcapNative_openDeadWithTstampPrecision(
  JNIEnv *env, jclass class, jint linktype, jint snaplen, jint precision) {
  return (jlong) pcap_open_dead_with_tstamp_precision(linktype, snaplen, precision);
}

JNIEXPORT void JNICALL Java_net_elytrium_pcap_PcapNative_close(JNIEnv *env, jclass class, jlong handle) {
  pcap_close((pcap_t *) handle);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_setSnaplen(JNIEnv *env, jclass class, jlong handle, jint snaplen) {
  return pcap_set_snaplen((pcap_t *) handle, snaplen);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_snapshot(JNIEnv *env, jclass class, jlong handle) {
  return pcap_snapshot((pcap_t *) handle);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_setPromisc(JNIEnv *env, jclass class, jlong handle, jint promisc) {
  return pcap_set_promisc((pcap_t *) handle, promisc);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_setProtocolLinux(JNIEnv *env, jclass class, jlong handle, jint protocol) {
  return pcap_set_protocol_linux((pcap_t *) handle, protocol);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_setRfmon(JNIEnv *env, jclass class, jlong handle, jint rfmon) {
  return pcap_set_rfmon((pcap_t *) handle, rfmon);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_canSetRfmon(JNIEnv *env, jclass class, jlong handle) {
  return pcap_can_set_rfmon((pcap_t *) handle);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_setTimeout(JNIEnv *env, jclass class, jlong handle, jint ms) {
  return pcap_set_timeout((pcap_t *) handle, ms);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_setImmediateMode(JNIEnv *env, jclass class, jlong handle, jint immediateMode) {
  return pcap_set_immediate_mode((pcap_t *) handle, immediateMode);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_setBufferSize(JNIEnv *env, jclass class, jlong handle, jint bufferSize) {
  return pcap_set_buffer_size((pcap_t *) handle, bufferSize);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_setTstampType(JNIEnv *env, jclass class, jlong handle, jint tstampType) {
  return pcap_set_tstamp_type((pcap_t *) handle, tstampType);
}

JNIEXPORT jlong JNICALL Java_net_elytrium_pcap_PcapNative_listTstampTypes(JNIEnv *env, jclass class, jlong handle, jintArray jlength) {
  int *types;
  int length = pcap_list_tstamp_types((pcap_t *) handle, &types);
  (*env)->SetIntArrayRegion(env, jlength, 0, 1, &length);
  return (jlong) types;
}

JNIEXPORT void JNICALL Java_net_elytrium_pcap_PcapNative_freeTstampTypes(JNIEnv *env, jclass class, jlong address) {
  pcap_free_tstamp_types((int *) address);
}

JNIEXPORT jstring JNICALL Java_net_elytrium_pcap_PcapNative_tstampTypeValToName(JNIEnv *env, jclass class, jint tstampType) {
  const char *name = pcap_tstamp_type_val_to_name(tstampType);
  if (name) {
    return (*env)->NewStringUTF(env, name);
  } else {
    return NULL;
  }
}

JNIEXPORT jstring JNICALL Java_net_elytrium_pcap_PcapNative_tstampTypeValToDescription(JNIEnv *env, jclass class, jint tstampType) {
  const char *description = pcap_tstamp_type_val_to_description(tstampType);
  if (description) {
    return (*env)->NewStringUTF(env, description);
  } else {
    return NULL;
  }
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_tstampTypeNameToVal(JNIEnv *env, jclass class, jstring jname) {
  const char *name = (*env)->GetStringUTFChars(env, jname, NULL);
  int value = pcap_tstamp_type_name_to_val(name);
  (*env)->ReleaseStringUTFChars(env, jname, name);
  return value;
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_setTstampPrecision(JNIEnv *env, jclass class, jlong handle, jint tstampPrecision) {
  return pcap_set_tstamp_precision((pcap_t *) handle, tstampPrecision);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_getTstampPrecision(JNIEnv *env, jclass class, jlong handle) {
  return pcap_get_tstamp_precision((pcap_t *) handle);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_datalink(JNIEnv *env, jclass class, jlong handle) {
  return pcap_datalink((pcap_t *) handle);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_file(JNIEnv *env, jclass class, jlong handle) {
  FILE *file = pcap_file((pcap_t *) handle);
  if (file) {
    return fileno(file);
  } else {
    return 0;
  }
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_isSwapped(JNIEnv *env, jclass class, jlong handle) {
  return pcap_is_swapped((pcap_t *) handle);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_majorVersion(JNIEnv *env, jclass class, jlong handle) {
  return pcap_major_version((pcap_t *) handle);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_minorVersion(JNIEnv *env, jclass class, jlong handle) {
  return pcap_minor_version((pcap_t *) handle);
}

JNIEXPORT jlong JNICALL Java_net_elytrium_pcap_PcapNative_listDatalinks(JNIEnv *env, jclass class, jlong handle, jintArray jlength) {
  int *datalinks;
  int length = pcap_list_datalinks((pcap_t *) handle, &datalinks);
  (*env)->SetIntArrayRegion(env, jlength, 0, 1, &length);
  return (jlong) datalinks;
}

JNIEXPORT void JNICALL Java_net_elytrium_pcap_PcapNative_freeDatalinks(JNIEnv *env, jclass class, jlong datalinks) {
  pcap_free_datalinks((int *) datalinks);
}

void pcap_handler_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes) {
  jni_callback_t *callback = (jni_callback_t *) user;
  JNIEnv *env = callback->env;
  jobject handler = callback->handler;

  static jmethodID method = NULL;
  if (!method) {
    jclass class = (*env)->FindClass(env, "net/elytrium/pcap/PcapHandler");
    method = (*env)->GetMethodID(env, class, "handleNative", "(JLjava/nio/ByteBuffer;)V");
  }

  jobject buffer = (*env)->NewDirectByteBuffer(env, (void *) bytes, header->len);
  (*env)->CallVoidMethod(env, handler, method, (jlong) header, buffer);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_loop(JNIEnv *env, jclass class, jlong handle, jint count, jobject handler) {
  jni_callback_t callback;
  callback.env = env;
  callback.handler = handler;
  return pcap_loop((pcap_t *) handle, count, pcap_handler_callback, (u_char *) &callback);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_dispatch(JNIEnv *env, jclass class, jlong handle, jint count, jobject handler) {
  jni_callback_t callback;
  callback.env = env;
  callback.handler = handler;
  return pcap_dispatch((pcap_t *) handle, count, pcap_handler_callback, (u_char *) &callback);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_next(JNIEnv *env, jclass class, jlong handle, jlongArray jheader, jobjectArray jbuffer) {
  struct pcap_pkthdr *header;
  const u_char *bytes;
  int status = pcap_next_ex((pcap_t *) handle, &header, &bytes);
  if (status < 0) {
    return status;
  }

  jobject buffer = (*env)->NewDirectByteBuffer(env, (void *) bytes, header->len);
  (*env)->SetLongArrayRegion(env, jheader, 0, 1, (jlong *) &header);
  (*env)->SetObjectArrayElement(env, jbuffer, 0, buffer);
  return status;
}

JNIEXPORT void JNICALL Java_net_elytrium_pcap_PcapNative_breakLoop(JNIEnv *env, jclass class, jlong handle) {
  pcap_breakloop((pcap_t *) handle);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_stats(JNIEnv *env, jclass class, jlong handle, jlong stats) {
  return pcap_stats((pcap_t *) handle, (struct pcap_stat *) stats);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_setFilter(JNIEnv *env, jclass class, jlong handle, jlong program) {
  return pcap_setfilter((pcap_t *) handle, (struct bpf_program *) program);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_setDirection(JNIEnv *env, jclass class, jlong handle, jint direction) {
  return pcap_setdirection((pcap_t *) handle, direction);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_getNonBlock(JNIEnv *env, jclass class, jlong handle) {
  return pcap_getnonblock((pcap_t *) handle, errbuf);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_setNonBlock(JNIEnv *env, jclass class, jlong handle, jint nonblock) {
  return pcap_setnonblock((pcap_t *) handle, nonblock, errbuf);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_inject(JNIEnv *env, jclass class, jlong handle, jobject buffer) {
  void *address = (*env)->GetDirectBufferAddress(env, buffer);
  jlong capacity = (*env)->GetDirectBufferCapacity(env, buffer);
  return pcap_inject((pcap_t *) handle, address, capacity);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_sendPacket(JNIEnv *env, jclass class, jlong handle, jobject buffer) {
  void *address = (*env)->GetDirectBufferAddress(env, buffer);
  jlong capacity = (*env)->GetDirectBufferCapacity(env, buffer);
  return pcap_sendpacket((pcap_t *) handle, address, (int) capacity);
}

JNIEXPORT jstring JNICALL Java_net_elytrium_pcap_PcapNative_statusToString(JNIEnv *env, jclass class, jint status) {
  return (*env)->NewStringUTF(env, pcap_statustostr(status));
}

JNIEXPORT jstring JNICALL Java_net_elytrium_pcap_PcapNative_stringError(JNIEnv *env, jclass class, jint error) {
  return (*env)->NewStringUTF(env, pcap_strerror(error));
}

JNIEXPORT jstring JNICALL Java_net_elytrium_pcap_PcapNative_stringErrorErrno(JNIEnv *env, jclass class) {
  return (*env)->NewStringUTF(env, pcap_strerror(errno));
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_compile(
  JNIEnv *env, jclass class, jlong handle, jlong program, jstring jstr, jint optimize, jint netmask) {
  const char *str = (*env)->GetStringUTFChars(env, jstr, NULL);
  int status = pcap_compile((pcap_t *) handle, (struct bpf_program *) program, str, optimize, netmask);
  (*env)->ReleaseStringUTFChars(env, jstr, str);
  return status;
}

JNIEXPORT void JNICALL Java_net_elytrium_pcap_PcapNative_freeCode(JNIEnv *env, jclass class, jlong handle) {
  pcap_freecode((struct bpf_program *) handle);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_offlineFilter(JNIEnv *env, jclass class, jlong program, jlong header, jobject buffer) {
  void *packet = (*env)->GetDirectBufferAddress(env, buffer);
  return pcap_offline_filter((struct bpf_program *) program, (struct pcap_pkthdr *) header, packet);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_setDatalink(JNIEnv *env, jclass class, jlong handle, jint datalink) {
  return pcap_set_datalink((pcap_t *) handle, datalink);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_datalinkNameToVal(JNIEnv *env, jclass class, jstring jname) {
  const char *name = (*env)->GetStringUTFChars(env, jname, NULL);
  jint value = pcap_datalink_name_to_val(name);
  (*env)->ReleaseStringUTFChars(env, jname, name);
  return value;
}

JNIEXPORT jstring JNICALL Java_net_elytrium_pcap_PcapNative_datalinkValToName(JNIEnv *env, jclass class, jint datalink) {
  return (*env)->NewStringUTF(env, pcap_datalink_val_to_name(datalink));
}

JNIEXPORT jstring JNICALL Java_net_elytrium_pcap_PcapNative_datalinkValToDescription(JNIEnv *env, jclass class, jint datalink) {
  return (*env)->NewStringUTF(env, pcap_datalink_val_to_description(datalink));
}

JNIEXPORT jstring JNICALL Java_net_elytrium_pcap_PcapNative_datalinkValToDescriptionOrDlt(JNIEnv *env, jclass class, jint datalink) {
  return (*env)->NewStringUTF(env, pcap_datalink_val_to_description_or_dlt(datalink));
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_fileno(JNIEnv *env, jclass class, jlong handle) {
  return pcap_fileno((pcap_t *) handle);
}

JNIEXPORT jlong JNICALL Java_net_elytrium_pcap_PcapNative_dumpOpen(JNIEnv *env, jclass class, jlong handle, jstring jfname) {
  const char *fname = (*env)->GetStringUTFChars(env, jfname, NULL);
  pcap_dumper_t *dumper = pcap_dump_open((pcap_t *) handle, fname);
  (*env)->ReleaseStringUTFChars(env, jfname, fname);
  return (jlong) dumper;
}

JNIEXPORT jlong JNICALL Java_net_elytrium_pcap_PcapNative_dumpOpenAppend(JNIEnv *env, jclass class, jlong handle, jstring jfname) {
  const char *fname = (*env)->GetStringUTFChars(env, jfname, NULL);
  pcap_dumper_t *dumper = pcap_dump_open_append((pcap_t *) handle, fname);
  (*env)->ReleaseStringUTFChars(env, jfname, fname);
  return (jlong) dumper;
}

JNIEXPORT jlong JNICALL Java_net_elytrium_pcap_PcapNative_dumpFtell(JNIEnv *env, jclass class, jlong handle) {
  return pcap_dump_ftell((pcap_dumper_t *) handle);
}

JNIEXPORT jint JNICALL Java_net_elytrium_pcap_PcapNative_dumpFlush(JNIEnv *env, jclass class, jlong handle) {
  return pcap_dump_flush((pcap_dumper_t *) handle);
}

JNIEXPORT void JNICALL Java_net_elytrium_pcap_PcapNative_dumpClose(JNIEnv *env, jclass class, jlong handle) {
  pcap_dump_close((pcap_dumper_t *) handle);
}

JNIEXPORT void JNICALL Java_net_elytrium_pcap_PcapNative_dump(JNIEnv *env, jclass class, jlong handle, jlong header, jobject buffer) {
  void *address = (*env)->GetDirectBufferAddress(env, buffer);
  pcap_dump((u_char *) handle, (struct pcap_pkthdr *) header, address);
}

JNIEXPORT jstring JNICALL Java_net_elytrium_pcap_PcapNative_libVersion(JNIEnv *env, jclass class) {
  return (*env)->NewStringUTF(env, pcap_lib_version());
}