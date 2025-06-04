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

/**
 * Utility class for common operations such as byte array conversion to ASCII, hex, and little-endian longs.
 */
public class ASMediaUtils {

	/**
	 * Converts a byte array to a long, assuming little-endian byte order.
	 *
	 * @param bytes the byte array to convert
	 * @return the resulting long value
	 */
	public static long littleEndianToLong(byte[] bytes) {
		long value = 0;
		for (int i = 0; i < bytes.length; i++) {
			value |= (bytes[i] & 0xFFL) << (8 * i);
		}
		return value;
	}

	/**
	 * Converts a byte array to a string of ASCII characters.
	 * Unprintable characters are represented as '.'.
	 *
	 * @param bytes the byte array to convert
	 * @return the resulting ASCII string
	 */
	public static String toAscii(byte[] bytes) {
		StringBuilder asciiBuilder = new StringBuilder();
		for (byte b : bytes) {
			if (b >= 32 && b <= 126) {
				// ASCII printable characters range
				asciiBuilder.append((char) b);
			} else {
				// Unprintable characters
				asciiBuilder.append('.');
			}
		}
		String asciiString = asciiBuilder.toString();
		return asciiString;
	}

	/**
	 * Converts a byte array to a hexadecimal string.
	 * Each byte is represented as two hex digits, separated by spaces.
	 *
	 * @param bytes the byte array to convert
	 * @return the resulting hex string
	 */
	public static String toHex(byte[] bytes) {
		StringBuilder hexBuilder = new StringBuilder();
		for (byte b : bytes) {
			hexBuilder.append(String.format("%02X ", b & 0xFF));
		}
		String hexString = hexBuilder.toString().trim();
		return hexString;
	}
}
