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

import java.awt.Component;
import javax.swing.JComboBox;

import ghidra.app.util.Option;
import ghidra.program.model.address.AddressFactory;

public class ASMediaFirmwareTypeOption extends Option {

	public ASMediaFirmwareTypeOption(String name, ASMediaFirmwareType defaultValue, String arg) {
		super(name, defaultValue, ASMediaFirmwareType.class, arg);
	}

	@Override
	public Component getCustomEditorComponent() {
		JComboBox<ASMediaFirmwareType> comboBox = new JComboBox<>(ASMediaFirmwareType.values());
		comboBox.setSelectedItem(getValue());
		comboBox.addActionListener(e -> {
			setValue(comboBox.getSelectedItem());
		});
		return comboBox;
	}

	@Override
	public Class<?> getValueClass() {
		return ASMediaFirmwareType.class;
	}

	@Override
	public Option copy() {
		return new ASMediaFirmwareTypeOption(getName(), (ASMediaFirmwareType) getValue(), getArg());
	}

	@Override
	public boolean parseAndSetValueByType(String str, AddressFactory addressFactory) {
		for (ASMediaFirmwareType type : ASMediaFirmwareType.values()) {
			if (type.toString().equalsIgnoreCase(str)) {
				setValue(type);
				return true;
			}
		}
		return false;
	}
}
