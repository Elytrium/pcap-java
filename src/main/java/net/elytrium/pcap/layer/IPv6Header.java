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

package net.elytrium.pcap.layer;

import java.util.function.Supplier;
import net.elytrium.pcap.layer.data.IpProtocol;

public abstract class IPv6Header implements Layer {

  protected IpProtocol nextHeader;

  public IpProtocol getNextHeader() {
    return this.nextHeader;
  }

  public void setNextHeader(IpProtocol nextHeader) {
    this.nextHeader = nextHeader;
  }

  @Override
  public Supplier<Layer> nextLayer() {
    return this.nextHeader != null ? this.nextHeader.getLayer() : null;
  }

  @Override
  public String toString() {
    return "IPv6Header{"
        + "nextHeader=" + this.nextHeader
        + '}';
  }
}
