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

import java.util.ArrayList;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer for processing and analyzing firmware binaries targeting ASMedia 8051 cores.
 * This analyzer is designed to work with both standard 8051 and ASMedia-specific 8051
 * processor architectures. It performs architecture-specific analysis during import.
 */
public class ASMedia8051Analyzer extends AbstractAnalyzer {

	private final static String NAME = "ASMedia 8051 Analyzer";
	private final static String DESCRIPTION = "Analyzes binaries for ASMedia 8051 cores";

	private final static String PROCESSOR_NAME_8051 = "8051";
	private final static String PROCESSOR_NAME_ASMEDIA = "ASMedia 8051";

	/**
	 * Constructs an ASMedia8051Analyzer instance.
	 * Initializes the analyzer with the specified name, description, and analyzer type.
	 * Configures it to support one-time analysis and prototype mode.
	 */
	public ASMedia8051Analyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setSupportsOneTimeAnalysis();
		setPrototype();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		Processor processor = program.getLanguage().getProcessor();

		// Only enable by default for programs we know are for ASMedia's 8051 cores.
		return processor.equals(Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME_ASMEDIA));
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor processor = program.getLanguage().getProcessor();

		// Only support analysis on standard 8051 cores and ASMedia's 8051 cores.
		return processor.equals(Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME_8051)) ||
			processor.equals(Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME_ASMEDIA));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.

		return true;
	}
}
