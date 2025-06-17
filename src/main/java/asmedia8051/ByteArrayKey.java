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

/**
 * A key type for uniquely identifying byte arrays.
 */
public class ByteArrayKey {
	private final byte[] value;

	/**
	 * Constructs a new ByteArrayKey with the specified byte array.
	 *
	 * @param value the byte array to store as the key
	 */
	public ByteArrayKey(byte[] value) {
		this.value = value;
	}

	/**
	 * Constructs a new ByteArrayKey from a string, converting it to a byte array
	 * using US-ASCII encoding.
	 *
	 * @param value the string to convert to a byte array
	 */
	public ByteArrayKey(String value) {
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
