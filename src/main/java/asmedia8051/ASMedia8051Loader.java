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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
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

/**
 * A loader for ASMedia 8051 firmware images. This class handles the parsing and memory layout
 * of firmware binaries based on detected firmware types (e.g., Promontory, Flash Image, or Raw Binary).
 */
public class ASMedia8051Loader extends AbstractProgramWrapperLoader {

	private final static String FIRMWARE_TYPE_OPTION_NAME = "Firmware Type";
	private final static ASMediaFirmwareType FIRMWARE_TYPE_OPTION_DEFAULT = ASMediaFirmwareType.AUTO;

	@Override
	public String getName() {
		return "ASMedia 8051 Firmware";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		String fileName = provider.getName();
		if (fileName != null && fileName.endsWith(".bin")) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ASMedia-8051:LE:24:default", "default"), true));
		}

		return loadSpecs;
	}

	private void loadFlashImage(ByteProvider provider, Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		long bodyOffset = ASMediaUtils.littleEndianToLong(provider.readBytes(4, 2)) + 5;

		byte[] headerMagic = provider.readBytes(6, 10);

		String asciiString = ASMediaUtils.toAscii(headerMagic);
		String hexString = ASMediaUtils.toHex(headerMagic);
		ASMediaXhcType type = ASMediaXhcType.getFromRcfgPlatformId(headerMagic);

		log.appendMsg("Platform detected from ROM config: " + type.toString() + " ( \"" + asciiString + "\" / [" + hexString + "] )");

		ASMediaXhcMetadata.RcfgChipMetadata rcfgMetadata = ASMediaXhcMetadata.getRcfgChipMetadata(type);
		long codeLen = ASMediaUtils.littleEndianToLong(provider.readBytes(bodyOffset, rcfgMetadata.codeLenSize()));
		long offset = bodyOffset + rcfgMetadata.codeLenSize();

		loadRawBinary(provider, offset, codeLen, type, program, monitor, log);
	}

	private void loadPromontoryImage(ByteProvider provider, Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		long bodyLen = ASMediaUtils.littleEndianToLong(provider.readBytes(4, 4)) - 12;
		long codeLen = bodyLen - (bodyLen & 0xff);  // Exclude the signature, if present

		loadRawBinary(provider, 12, codeLen, ASMediaXhcType.UNKNOWN, program, monitor, log);
	}

	private void loadRawBinary(ByteProvider provider, Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		loadRawBinary(provider, 0, provider.length(), ASMediaXhcType.UNKNOWN, program, monitor, log);
	}

	private void loadRawBinary(ByteProvider provider, long offset, long length, ASMediaXhcType identifiedType,
			Program program, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		Memory mem = program.getMemory();
		FlatProgramAPI api = new FlatProgramAPI(program);
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, offset, length, monitor);

		long fileSize = fileBytes.getSize();

		try {
			// Load the CODE blocks

			// First 0xC000 bytes are the common bank
			int firstChunkSize = Math.min(0xC000, (int)fileSize);
			MemoryBlock com = mem.createInitializedBlock("BANK_COM", api.toAddr("CODE:0x0000"),
				fileBytes, 0, firstChunkSize, false);
			com.setPermissions(true, false, true);
			com.setVolatile(false);

			// Remaining bytes in 0x4000 chunks
			long remainingSize = fileSize - firstChunkSize;
			int bankCount = (int)(remainingSize / 0x4000);
			if (remainingSize % 0x4000 > 0) {
				bankCount += 1;
			}
			long offsetInFile = firstChunkSize;
			for (int i = 0; i < bankCount; i++) {
				int chunkSize = Math.min(0x4000, (int)(fileSize - offsetInFile));

				MemoryBlock bank = mem.createInitializedBlock("BANK_" + i, api.toAddr("CODE:0xC000"),
					fileBytes, offsetInFile, chunkSize, i > 0);
				bank.setPermissions(true, false, true);
				bank.setVolatile(false);

				offsetInFile += chunkSize;
			}

			ASMediaXhcType type = identifiedType;
			if (type == ASMediaXhcType.UNKNOWN) {
				// Read firmware platform ID
				byte[] platformIdBytes = provider.readBytes(offset + 0x87, 8);

				// Get the chip type from the firmware platform ID
				type = ASMediaXhcType.getFromFwPlatformId(platformIdBytes);

				// Tell the user what platform was detected
				String platformIdString = ASMediaUtils.toAscii(platformIdBytes);
				String platformIdHex = ASMediaUtils.toHex(platformIdBytes);
				log.appendMsg("Platform detected from firmware: " + type.toString() + " ( \"" + platformIdString + "\" / [" + platformIdHex + "] )");
			}

			// Lookup chip metadata
			ASMediaXhcMetadata.FwChipMetadata metadata = ASMediaXhcMetadata.getFwChipMetadata(type);

			// Load XRAM and MMIO blocks based on metadata
			for (ASMediaXhcMetadata.MemoryRegion region : metadata.regions()) {
				MemoryBlock block = mem.createUninitializedBlock(region.name(), api.toAddr("EXTMEM:0x" + Long.toHexString(region.baseAddress())), region.size(), false);
				block.setPermissions(true, true, false);
				block.setVolatile(true);
			}

		} catch (AddressOverflowException | LockException | MemoryConflictException e) {
			throw new IOException(e);
		}
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		boolean hasPromontoryMagic = false;
		if (provider.length() >= 4) {
			byte[] pt_magic = provider.readBytes(0, 4);
			hasPromontoryMagic = Arrays.equals(pt_magic, ASMediaUtils.toBytes("_PT_"));
		}

		boolean hasRcfgMagic = false;
		if (provider.length() >= 16) {
			byte[] rcfg_magic = provider.readBytes(11, 5);
			hasRcfgMagic = Arrays.equals(rcfg_magic, ASMediaUtils.toBytes("_RCFG"));
		}

		ASMediaFirmwareType firmwareType = OptionUtils.getOption(FIRMWARE_TYPE_OPTION_NAME, options, FIRMWARE_TYPE_OPTION_DEFAULT);
		switch (firmwareType) {
			case ASMediaFirmwareType.AUTO, ASMediaFirmwareType.IMAGE -> {
				if (hasPromontoryMagic) {
					// Promontory image
					log.appendMsg("Detected firmware type: Promontory");
					loadPromontoryImage(provider, program, monitor, log);
				} else if (hasRcfgMagic) {
					// Regular flash image
					log.appendMsg("Detected firmware type: Flash Image");
					loadFlashImage(provider, program, monitor, log);
				} else {
					// Raw binary
					if (firmwareType == ASMediaFirmwareType.IMAGE) {
						throw new IOException("Binary is not a valid firmware image.");
					}
					log.appendMsg("Detected firmware type: Raw Binary");
					loadRawBinary(provider, program, monitor, log);
				}
			}
			case ASMediaFirmwareType.RAW -> loadRawBinary(provider, program, monitor, log);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		list.add(new ASMediaFirmwareTypeOption(FIRMWARE_TYPE_OPTION_NAME, FIRMWARE_TYPE_OPTION_DEFAULT,
			Loader.COMMAND_LINE_ARG_PREFIX + "-firmwareType"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(FIRMWARE_TYPE_OPTION_NAME)) {
					if (!ASMediaFirmwareType.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
			}
		}

		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	public boolean shouldApplyProcessorLabelsByDefault() {
		return true;
	}
}
