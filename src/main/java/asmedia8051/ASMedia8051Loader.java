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

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ASMedia8051Loader extends AbstractProgramWrapperLoader {

	@Override
	public String getName() {
		return "ASMedia 8051 Firmware";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ASMedia-8051:LE:24:default", "default"), true));

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		Memory mem = program.getMemory();
		FlatProgramAPI api = new FlatProgramAPI(program);

		long fileSize = provider.length();

		try {
			// Load the CODE blocks

			// First 0xC000 bytes are the common bank
			int firstChunkSize = Math.min(0xC000, (int)fileSize);
			MemoryBlock com = mem.createInitializedBlock("BANK_COM", api.toAddr("CODE:0x0000"),
				provider.getInputStream(0), firstChunkSize, monitor, false);
			com.setPermissions(true, false, true);
			com.setVolatile(false);
			com.setSourceName(provider.getName() + formatAddressRange(0, firstChunkSize));

			// Remaining bytes in 0x4000 chunks
			int bankCount = (int)((fileSize - firstChunkSize) / 0x4000);
			long offsetInFile = firstChunkSize;
			for(int i = 0; i < bankCount; i++) {
				int chunkSize = Math.min(0x4000, (int)(fileSize - offsetInFile));

				MemoryBlock bank = mem.createInitializedBlock("BANK_" + i, api.toAddr("CODE:0xC000"),
					provider.getInputStream(offsetInFile), chunkSize, monitor, i > 0);
				bank.setPermissions(true, false, true);
				bank.setVolatile(false);
				bank.setSourceName(provider.getName() + formatAddressRange(offsetInFile, chunkSize));

				offsetInFile += chunkSize;
			}

			// Create the XRAM and MMIO blocks
			MemoryBlock xram = mem.createUninitializedBlock("XRAM", api.toAddr("EXTMEM:0x000000"), 0x10000, false);
			xram.setPermissions(true, true, false);
			xram.setVolatile(true);  // We treat XRAM as volatile since it can be modified by DMA from peripherals.

			MemoryBlock mmio = mem.createUninitializedBlock("MMIO", api.toAddr("EXTMEM:0x010000"), 0x10000, false);
			mmio.setPermissions(true, true, false);
			mmio.setVolatile(true);

		} catch (AddressOverflowException | LockException | MemoryConflictException e) {
			log.appendException(e);
		}
	}

	private static String formatAddressRange(long start, long length) {
		return String.format("[0x%x, 0x%x]", start, length);
	}
}
