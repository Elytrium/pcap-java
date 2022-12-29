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

public enum IPv4OptionType {
  EOOL(0, 0, 0),
  NOP(0, 0, 1),
  SEC(1, 0, 2),
  LSR(1, 0, 3),
  TS(0, 2, 4),
  E_SEC(1, 0, 5),
  CIPSO(1, 0, 6),
  RR(0, 0, 7),
  SID(1, 0, 8),
  SSR(1, 0, 9),
  ZSU(0, 0, 10),
  MTUP(0, 0, 11),
  MTUR(0, 0, 12),
  FINN(1, 2, 13),
  VISA(1, 0, 14),
  ENCODE(0, 0, 15),
  IMITD(1, 0, 16),
  EIP(1, 0, 17),
  TR(0, 2, 18),
  ADDEXT(1, 0, 19),
  RTRALT(1, 0, 20),
  SDB(1, 0, 21),
  B7(1, 0, 22),
  DPS(1, 0, 23),
  UMP(1, 0, 24),
  QS(0, 0, 25),
  EXP(0, 0, 30),
  EXP2(0, 2, 30),
  EXPC(1, 0, 30),
  EXP2C(1, 2, 30);

  private static final Map<Integer, IPv4OptionType> REGISTRY = new HashMap<>();

  static {
    for (IPv4OptionType option : values()) {
      REGISTRY.put(option.getValue(), option);
    }
  }

  private final int copy;
  private final int optionClass;
  private final int optionNumber;
  private final int value;

  IPv4OptionType(int copy, int optionClass, int optionNumber) {
    this.copy = copy;
    this.optionClass = optionClass;
    this.optionNumber = optionNumber;
    this.value = optionNumber | (optionClass << 5) | (copy << 7);
  }

  public int getCopy() {
    return this.copy;
  }

  public int getOptionClass() {
    return this.optionClass;
  }

  public int getOptionNumber() {
    return this.optionNumber;
  }

  public int getValue() {
    return this.value;
  }

  public static IPv4OptionType getByValue(int value) {
    return REGISTRY.get(value);
  }
}
