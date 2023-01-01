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

package net.elytrium.pcap.layer;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import net.elytrium.pcap.layer.data.LinkType;
import net.elytrium.pcap.layer.exception.LayerDecodeException;
import net.elytrium.pcap.layer.exception.LayerEncodeException;

public class Packet {

  private final Map<Class<? extends Layer>, List<Layer>> layerMap = new HashMap<>();
  private final List<Layer> layers = new ArrayList<>();
  private ByteBuffer data;

  public Packet(List<Layer> layers, ByteBuffer data) {
    this.data = data;
    layers.forEach(this::addLayer);
  }

  public Packet() {
  }

  public void decode(ByteBuffer buffer, Supplier<Layer> first) throws LayerDecodeException {
    this.layerMap.clear();
    this.layers.clear();

    Supplier<Layer> supplier = first;
    while (supplier != null) {
      Layer layer = supplier.get();
      layer.decode(buffer);
      this.addLayer(layer);
      supplier = layer.nextLayer();
    }

    this.data = ByteBuffer.allocate(buffer.remaining());
    this.data.put(buffer);
    this.data.flip();
  }

  public void decode(ByteBuffer buffer, LinkType linkType) throws LayerDecodeException {
    this.decode(buffer, linkType.getLayer());
  }

  public ByteBuffer encode(ByteBuffer buffer) throws LayerEncodeException {
    for (Layer layer : this.layers) {
      layer.encode(buffer);
    }

    if (this.data != null) {
      buffer.put(this.data);
    }

    return buffer;
  }

  public ByteBuffer encode() throws LayerEncodeException {
    return this.encode(ByteBuffer.allocateDirect(this.getSize()));
  }

  public int getSize() {
    return this.data.remaining() + this.layers.stream().mapToInt(Layer::getSize).sum();
  }

  public void addLayer(Layer layer) {
    this.layerMap.computeIfAbsent(layer.getClass(), k -> new ArrayList<>()).add(layer);
    this.layers.add(layer);
  }

  public List<Layer> getLayers() {
    return this.layers;
  }

  public List<Layer> getLayers(Class<? extends Layer> cls) {
    return this.layerMap.get(cls);
  }

  public Map<Class<? extends Layer>, List<Layer>> getLayerMap() {
    return this.layerMap;
  }

  public ByteBuffer getData() {
    return this.data;
  }

  public void setData(ByteBuffer data) {
    this.data = data;
  }

  @Override
  public String toString() {
    return "Packet{"
        + "layers=" + this.layers
        + ", data=" + this.data
        + '}';
  }
}
