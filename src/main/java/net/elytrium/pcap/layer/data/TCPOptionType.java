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

public enum TCPOptionType {
  EOOL(0, false),
  NOOP(1, false),
  MSS(2),
  WS(3),
  SACKP(4),
  SACK(5),
  TS(8),
  TFO(34);

  private static final Map<Integer, TCPOptionType> REGISTRY = new HashMap<>();

  static {
    for (TCPOptionType option : values()) {
      REGISTRY.put(option.getValue(), option);
    }
  }

  private final int value;
  private final boolean hasData;

  TCPOptionType(int value, boolean hasData) {
    this.value = value;
    this.hasData = hasData;
  }

  TCPOptionType(int value) {
    this.value = value;
    this.hasData = true;
  }

  public int getValue() {
    return this.value;
  }

  public boolean hasData() {
    return this.hasData;
  }

  public static TCPOptionType getByValue(int value) {
    return REGISTRY.get(value);
  }
}
