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

	/**
	 * Metadata describing a specific chip, including its name and associated memory regions.
	 *
	 * @param name the name of the chip (e.g., "ASM1042", "Promontory")
	 * @param regions a list of memory regions defined for this chip
	 */
	public record FwChipMetadata(String name, List<MemoryRegion> regions) {}

	/**
	 * Represents a memory region with a name, base address, and size.
	 *
	 * @param name the name of the memory region (e.g., "XRAM", "MMIO")
	 * @param baseAddress the starting address of the memory region
	 * @param size the size of the memory region in bytes
	 */
	public record MemoryRegion(String name, long baseAddress, long size) {}

	private static final FwChipMetadata DEFAULT_FW_CHIP_METADATA = new FwChipMetadata(
		"UNKNOWN",
		List.of(
			new MemoryRegion("XRAM", 0x000000, 0x10000),
			new MemoryRegion("MMIO", 0x010000, 0x10000)
		)
	);

	private static final Map<ASMediaXhcType, FwChipMetadata> FW_CHIP_METADATA = Map.ofEntries(
		Map.entry(ASMediaXhcType.ASM1042, new FwChipMetadata("ASM1042", List.of(
			new MemoryRegion("XRAM", 0x0000, 0xC000),
			new MemoryRegion("MMIO", 0xE000, 0x2000)
		))),
		Map.entry(ASMediaXhcType.ASM1042A, new FwChipMetadata("ASM1042A", List.of(
			new MemoryRegion("XRAM", 0x0000, 0xC000),
			new MemoryRegion("MMIO", 0xE000, 0x2000)
		))),
		Map.entry(ASMediaXhcType.ASM1142, new FwChipMetadata("ASM1142", List.of(
			new MemoryRegion("XRAM", 0x0000, 0xC000),
			new MemoryRegion("MMIO", 0xE000, 0x2000)
		))),
		Map.entry(ASMediaXhcType.ASM2142_ASM3142, new FwChipMetadata("ASM2142/ASM3142", List.of(
			new MemoryRegion("XRAM", 0x000000, 0x0C000),
			new MemoryRegion("MMIO", 0x010000, 0x10000)
		))),
		Map.entry(ASMediaXhcType.ASM3242, new FwChipMetadata("ASM3242", List.of(
			/* FIXME: Assumed size of XRAM, need to confirm on real hardware */
			new MemoryRegion("XRAM", 0x000000, 0x10000),
			new MemoryRegion("MMIO", 0x010000, 0x10000)
		))),
		Map.entry(ASMediaXhcType.PROM, new FwChipMetadata("Promontory", List.of(
			/* FIXME: Assumed size of XRAM, need to confirm on real hardware */
			new MemoryRegion("XRAM", 0x000000, 0x10000),
			new MemoryRegion("MMIO", 0x010000, 0x10000)
		))),
		Map.entry(ASMediaXhcType.PROM_LP, new FwChipMetadata("Promontory-LP", List.of(
			/* FIXME: Assumed size of XRAM, need to confirm on real hardware */
			new MemoryRegion("XRAM", 0x000000, 0x10000),
			new MemoryRegion("MMIO", 0x010000, 0x10000)
		))),
		Map.entry(ASMediaXhcType.PROM_19, new FwChipMetadata("Promontory-19", List.of(
			/* FIXME: Assumed size of XRAM, need to confirm on real hardware */
			new MemoryRegion("XRAM", 0x000000, 0x10000),
			new MemoryRegion("MMIO", 0x010000, 0x10000)
		))),
		Map.entry(ASMediaXhcType.PROM_21, new FwChipMetadata("Promontory-21", List.of(
			/* FIXME: Assumed size of XRAM, need to confirm on real hardware */
			new MemoryRegion("XRAM",      0x000000, 0x10000),
			new MemoryRegion("MMIO_USB",  0x010000, 0x10000),
			new MemoryRegion("MMIO_SATA", 0x020000, 0x10000)
		)))
	);

	/**
	 * Returns the FwChipMetadata for the given firmware platform ID bytes.
	 *
	 * @param platformIdBytes the platform ID bytes to look up
	 * @return the corresponding FwChipMetadata, or the default if not found
	 */
	public static FwChipMetadata getFwChipMetadata(byte[] platformIdBytes) {
		ASMediaXhcType type = ASMediaXhcType.getFromFwPlatformId(platformIdBytes);
		return FW_CHIP_METADATA.getOrDefault(type, DEFAULT_FW_CHIP_METADATA);
	}

	/**
	 * A record to hold chip metadata for ROM config (RCFG) firmware.
	 *
	 * @param name the name of the chip (e.g., "ASM1042", "Promontory")
	 * @param codeLenSize the size in bytes used to represent the code length
	 */
	public record RcfgChipMetadata(String name, int codeLenSize) {}

	private static final RcfgChipMetadata DEFAULT_RCFG_CHIP_METADATA = new RcfgChipMetadata("UNKNOWN", 4);

	private static final Map<ASMediaXhcType, RcfgChipMetadata> RCFG_CHIP_METADATA = Map.ofEntries(
		Map.entry(ASMediaXhcType.ASM1042, new RcfgChipMetadata("ASM1042", 2)),
		Map.entry(ASMediaXhcType.ASM1042A, new RcfgChipMetadata("ASM1042A", 2)),
		Map.entry(ASMediaXhcType.ASM1142, new RcfgChipMetadata("ASM1142", 2)),
		Map.entry(ASMediaXhcType.ASM2142_ASM3142, new RcfgChipMetadata("ASM2142/ASM3142", 4)),
		Map.entry(ASMediaXhcType.ASM3242, new RcfgChipMetadata("ASM3242", 4))
	);

	/**
	 * Returns the RcfgChipMetadata for the given ROM config platform ID bytes.
	 * Defaults to the unknown metadata if no match is found.
	 *
	 * @param platformIdBytes the platform ID bytes to look up
	 * @return the corresponding RcfgChipMetadata
	 */
	public static RcfgChipMetadata getRcfgChipMetadata(byte[] platformIdBytes) {
		ASMediaXhcType type = ASMediaXhcType.getFromRcfgPlatformId(platformIdBytes);
		return RCFG_CHIP_METADATA.getOrDefault(type, DEFAULT_RCFG_CHIP_METADATA);
	}

}
