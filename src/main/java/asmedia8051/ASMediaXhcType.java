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

import java.util.Map;

/**
 * Enum representing known ASMedia xHC chip types.
 * Provides methods to identify chip types based on firmware or ROM config platform ID bytes.
 */
public enum ASMediaXhcType {
	ASM1042("ASM1042"),
	ASM1042A("ASM1042A"),
	ASM1142("ASM1142"),
	ASM2142_ASM3142("ASM2142/ASM3142"),
	ASM3242("ASM3242"),
	PROM("Promontory"),
	PROM_LP("Promontory-LP"),
	PROM_19("Promontory-19"),
	PROM_21("Promontory-21"),
	UNKNOWN("Unknown");

	private final String name;

	private static final Map<ByteArrayKey, ASMediaXhcType> FW_MAP = Map.ofEntries(
		Map.entry(new ByteArrayKey(new byte[]{0, 0, 0, 0, 0, 0, 0, 0}), ASM1042),
		Map.entry(new ByteArrayKey("2104B_FW"), ASM1042A),
		Map.entry(new ByteArrayKey("2114A_FW"), ASM1142),
		Map.entry(new ByteArrayKey("2214A_FW"), ASM2142_ASM3142),
		Map.entry(new ByteArrayKey("2324A_FW"), ASM3242),
		Map.entry(new ByteArrayKey("3306A_FW"), PROM),
		Map.entry(new ByteArrayKey("3306B_FW"), PROM_LP),
		Map.entry(new ByteArrayKey("3308A_FW"), PROM_19),
		Map.entry(new ByteArrayKey("3328A_FW"), PROM_21)
	);

	private static final Map<ByteArrayKey, ASMediaXhcType> RCFG_MAP = Map.ofEntries(
		Map.entry(new ByteArrayKey("U2104_RCFG"), ASM1042),
		Map.entry(new ByteArrayKey("2104B_RCFG"), ASM1042A),
		Map.entry(new ByteArrayKey("2114A_RCFG"), ASM1142),
		Map.entry(new ByteArrayKey("2214A_RCFG"), ASM2142_ASM3142),
		Map.entry(new ByteArrayKey("2324A_RCFG"), ASM3242)
	);

	ASMediaXhcType(String name) {
		this.name = name;
	}

	@Override
	public String toString() {
		return name;
	}

	/**
	 * Returns the ASMediaXhcType based on firmware platform ID bytes.
	 */
	public static ASMediaXhcType getFromFwPlatformId(byte[] platformIdBytes) {
		return FW_MAP.getOrDefault(new ByteArrayKey(platformIdBytes), UNKNOWN);
	}

	/**
	 * Returns the ASMediaXhcType based on ROM config platform ID bytes.
	 */
	public static ASMediaXhcType getFromRcfgPlatformId(byte[] platformIdBytes) {
		return RCFG_MAP.getOrDefault(new ByteArrayKey(platformIdBytes), UNKNOWN);
	}
}
