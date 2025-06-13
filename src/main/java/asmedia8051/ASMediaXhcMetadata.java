// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2025 Forest Crossman <cyrozap@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package asmedia8051;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Centralized metadata management for ASMedia xHC and Promontory platforms.
 * Provides platform-specific memory region definitions.
 */
public class ASMediaXhcMetadata {

	private static final class ByteArrayKey {
		private final byte[] value;

		private ByteArrayKey(byte[] value) {
			this.value = value;
		}

		private ByteArrayKey(String value) {
			this(value.getBytes(StandardCharsets.US_ASCII));
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (!(o instanceof ByteArrayKey)) return false;
			return Arrays.equals(value, ((ByteArrayKey) o).value);
		}

		@Override
		public int hashCode() {
			return Arrays.hashCode(value);
		}
	}

	/**
	 * Metadata describing a specific chip, including its name and associated memory regions.
	 *
	 * @param name the name of the chip (e.g., "ASM1042", "Promontory")
	 * @param regions a list of memory regions defined for this chip
	 */
	public record ChipMetadata(String name, List<MemoryRegion> regions) {}

	/**
	 * Represents a memory region with a name, base address, and size.
	 *
	 * @param name the name of the memory region (e.g., "XRAM", "MMIO")
	 * @param baseAddress the starting address of the memory region
	 * @param size the size of the memory region in bytes
	 */
	public record MemoryRegion(String name, long baseAddress, long size) {}

	private static final ChipMetadata DEFAULT_CHIP_METADATA = new ChipMetadata(
		"UNKNOWN",
		List.of(
			new MemoryRegion("XRAM", 0x000000, 0x10000),
			new MemoryRegion("MMIO", 0x010000, 0x10000)
		)
	);

	private static final Map<ByteArrayKey, ChipMetadata> CHIP_METADATA = Map.ofEntries(
		Map.entry(
			new ByteArrayKey(new byte[]{0, 0, 0, 0, 0, 0, 0, 0}),
			new ChipMetadata("ASM1042", List.of(
				new MemoryRegion("XRAM", 0x0000, 0xC000),
				new MemoryRegion("MMIO", 0xE000, 0x2000)
			))
		),
		Map.entry(
			new ByteArrayKey("2104B_FW"),
			new ChipMetadata("ASM1042A", List.of(
				new MemoryRegion("XRAM", 0x0000, 0xC000),
				new MemoryRegion("MMIO", 0xE000, 0x2000)
			))
		),
		Map.entry(
			new ByteArrayKey("2114A_FW"),
			new ChipMetadata("ASM1142", List.of(
				new MemoryRegion("XRAM", 0x0000, 0xC000),
				new MemoryRegion("MMIO", 0xE000, 0x2000)
			))
		),
		Map.entry(
			new ByteArrayKey("2214A_FW"),
			new ChipMetadata("ASM2142/ASM3142", List.of(
				new MemoryRegion("XRAM", 0x000000, 0x0C000),
				new MemoryRegion("MMIO", 0x010000, 0x10000)
			))
		),
		Map.entry(
			new ByteArrayKey("2324A_FW"),
			new ChipMetadata("ASM3242", List.of(
				/* FIXME: Assumed size of XRAM, need to confirm on real hardware */
				new MemoryRegion("XRAM", 0x000000, 0x10000),
				new MemoryRegion("MMIO", 0x010000, 0x10000)
			))
		),
		Map.entry(
			new ByteArrayKey("3306A_FW"),
			new ChipMetadata("Promontory", List.of(
				/* FIXME: Assumed layout, need to confirm on real hardware */
				new MemoryRegion("XRAM",      0x000000, 0x10000),
				new MemoryRegion("MMIO_USB",  0x010000, 0x10000),
				new MemoryRegion("MMIO_SATA", 0x020000, 0x10000)
			))
		),
		Map.entry(
			new ByteArrayKey("3306B_FW"),
			new ChipMetadata("Promontory-LP", List.of(
				/* FIXME: Assumed layout, need to confirm on real hardware */
				new MemoryRegion("XRAM",      0x000000, 0x10000),
				new MemoryRegion("MMIO_USB",  0x010000, 0x10000),
				new MemoryRegion("MMIO_SATA", 0x020000, 0x10000)
			))
		),
		Map.entry(
			new ByteArrayKey("3308A_FW"),
			new ChipMetadata("Promontory-19", List.of(
				/* FIXME: Assumed layout, need to confirm on real hardware */
				new MemoryRegion("XRAM",      0x000000, 0x10000),
				new MemoryRegion("MMIO_USB",  0x010000, 0x10000),
				new MemoryRegion("MMIO_SATA", 0x020000, 0x10000)
			))
		),
		Map.entry(
			new ByteArrayKey("3328A_FW"),
			new ChipMetadata("Promontory-21", List.of(
				/* FIXME: Assumed size of XRAM, need to confirm on real hardware */
				new MemoryRegion("XRAM",      0x000000, 0x10000),
				new MemoryRegion("MMIO_USB",  0x010000, 0x10000),
				new MemoryRegion("MMIO_SATA", 0x020000, 0x10000)
			))
		)
	);

	/**
	 * Returns the ChipMetadata for the given firmware platform ID bytes.
	 *
	 * @param platformIdBytes the platform ID bytes to look up
	 * @return the corresponding ChipMetadata, or the default if not found
	 */
	public static ChipMetadata get(byte[] platformIdBytes) {
		return CHIP_METADATA.getOrDefault(new ByteArrayKey(platformIdBytes), DEFAULT_CHIP_METADATA);
	}

	private static final Map<ByteArrayKey, Integer> HEADER_MAGIC_TO_CODE_LEN_SIZE = Map.ofEntries(
		Map.entry(new ByteArrayKey("U2104_RCFG"), 2),
		Map.entry(new ByteArrayKey("2104B_RCFG"), 2),
		Map.entry(new ByteArrayKey("2114A_RCFG"), 2)
	);

	/**
	 * Returns the code length size for the given ROM config platform ID bytes.
	 * Defaults to 4 if no match is found.
	 *
	 * @param platformIdBytes the platform ID bytes to look up
	 * @return the code length size
	 */
	public static int getCodeLenSize(byte[] platformIdBytes) {
		return HEADER_MAGIC_TO_CODE_LEN_SIZE.getOrDefault(new ByteArrayKey(platformIdBytes), 4);
	}

}
