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

package net.elytrium.pcap.data;

import net.elytrium.pcap.PcapException;

public enum PcapError {
  SUCCESS,
  ERROR_GENERIC,
  ERROR_BREAK,
  ERROR_NOT_ACTIVATED,
  ERROR_ACTIVATED,
  ERROR_NO_SUCH_DEVICE,
  ERROR_RFMON_NOTSUP,
  ERROR_NOT_RFMON,
  ERROR_PERM_DENIED,
  ERROR_IFACE_NOT_UP,
  ERROR_CANTSET_TSTAMP_TYPE,
  ERROR_PROMISC_PERM_DENIED,
  ERROR_TSTAMP_PRECISION_NOTSUP,
  WARNING_GENERIC,
  WARNING_PROMISC_NOTSUP,
  WARNING_TSTAMP_TYPE_NOTSUP;

  public int getValue() {
    if (this == SUCCESS) {
      return 0;
    } else if (this.isError()) {
      return -this.ordinal();
    } else {
      return this.ordinal() - 12;
    }
  }

  public boolean isWarning() {
    return ordinal() > 12;
  }

  public boolean isError() {
    return this != SUCCESS && !this.isWarning();
  }

  public boolean isGeneric() {
    return this == ERROR_GENERIC || this == WARNING_GENERIC;
  }

  public static PcapError fromCode(int code) {
    if (code == 0) {
      return SUCCESS;
    } else if (code < 0) {
      return values()[-code];
    } else {
      return values()[12 + code];
    }
  }

  public static PcapError throwIfNotSuccess(PcapError error) throws PcapException {
    if (error != SUCCESS) {
      throw new PcapException(error);
    }

    return error;
  }

  public static PcapError throwIfNotSuccess(int code) throws PcapException {
    return throwIfNotSuccess(fromCode(code));
  }

  public static PcapError throwIfError(PcapError error) throws PcapException {
    if (error != null && error.isError()) {
      throw new PcapException(error);
    }

    return error;
  }

  public static PcapError throwIfError(int code) throws PcapException {
    return throwIfError(fromCode(code));
  }
}
