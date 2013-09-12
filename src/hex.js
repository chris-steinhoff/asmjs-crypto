/**
 * User: Chris Steinhoff
 * Date: 9/2/13
 */

"use strict";

var Hex = function() {
	/**
	 * @param {window} stdlib
	 * @param {*} foreign
	 * @param {ArrayBuffer} heap
	 * @returns {{toHex: Function, fromHex: Function}}
	 */
	function hexAsm(stdlib, foreign, heap) {
		"use asm";

		var view8 = new stdlib.Uint8Array(heap);

		/**
		 * @param {int} offset Pointer to the beginning of the data in the heap.
		 * @param {int} len Length of the data.
		 * @returns {int} Pointer to the beginning of the converted data in the heap.
		 */
		function toHex(offset, len) {
			offset = offset|0; // heap read-pointer.
			len = len|0; // number of bytes to read.
			var p = 0; p = (offset + len)|0; // heap write-pointer.
			for( ; (len|0) > 0 ; len = (len - 1)|0, offset = (offset + 1)|0) {
				switch(((view8[offset] >>> 4) & 0xf)|0) {
				case  0: view8[p] = 0x30; break;
				case  1: view8[p] = 0x31; break;
				case  2: view8[p] = 0x32; break;
				case  3: view8[p] = 0x33; break;
				case  4: view8[p] = 0x34; break;
				case  5: view8[p] = 0x35; break;
				case  6: view8[p] = 0x36; break;
				case  7: view8[p] = 0x37; break;
				case  8: view8[p] = 0x38; break;
				case  9: view8[p] = 0x39; break;
				case 10: view8[p] = 0x61; break;
				case 11: view8[p] = 0x62; break;
				case 12: view8[p] = 0x63; break;
				case 13: view8[p] = 0x64; break;
				case 14: view8[p] = 0x65; break;
				case 15: view8[p] = 0x66; break;
				}
				p = (p + 1)|0;
				switch((view8[offset] & 0xf)|0) {
				case  0: view8[p] = 0x30; break;
				case  1: view8[p] = 0x31; break;
				case  2: view8[p] = 0x32; break;
				case  3: view8[p] = 0x33; break;
				case  4: view8[p] = 0x34; break;
				case  5: view8[p] = 0x35; break;
				case  6: view8[p] = 0x36; break;
				case  7: view8[p] = 0x37; break;
				case  8: view8[p] = 0x38; break;
				case  9: view8[p] = 0x39; break;
				case 10: view8[p] = 0x61; break;
				case 11: view8[p] = 0x62; break;
				case 12: view8[p] = 0x63; break;
				case 13: view8[p] = 0x64; break;
				case 14: view8[p] = 0x65; break;
				case 15: view8[p] = 0x66; break;
				}
				p = (p + 1)|0;
			}
			return offset|0;
		}

		/**
		 * @param {int} offset Pointer to the beginning of the data in the heap.
		 * @param {int} len Length of the data.
		 * @returns {int} Pointer to the beginning of the converted data in the heap.
		 *                The length of the converted data is len/4.
		 */
		function fromHex(offset, len) {
			offset = offset|0; // heap read-pointer.
			len = len|0; // number of nibbles to read.
			var p = 0; p = (offset + len)|0; // heap write-pointer.
			// Read every other byte, two at a time
			// len -= 4 because we're processing 4 bytes per iteration
			for( ; (len|0) > 0 ; len = (len - 4)|0, p = (p + 1)|0) {
				// Read the first nibble of the byte
				switch(view8[offset]|0) {
				case 0x30: view8[p] =  0 << 4; break;
				case 0x31: view8[p] =  1 << 4; break;
				case 0x32: view8[p] =  2 << 4; break;
				case 0x33: view8[p] =  3 << 4; break;
				case 0x34: view8[p] =  4 << 4; break;
				case 0x35: view8[p] =  5 << 4; break;
				case 0x36: view8[p] =  6 << 4; break;
				case 0x37: view8[p] =  7 << 4; break;
				case 0x38: view8[p] =  8 << 4; break;
				case 0x39: view8[p] =  9 << 4; break;
				case 0x61: view8[p] = 10 << 4; break;
				case 0x62: view8[p] = 11 << 4; break;
				case 0x63: view8[p] = 12 << 4; break;
				case 0x64: view8[p] = 13 << 4; break;
				case 0x65: view8[p] = 14 << 4; break;
				case 0x66: view8[p] = 15 << 4; break;
				}
				// Skip the next byte because it's always 0.
				offset = (offset + 2)|0;
				// Read the second nibble of the byte
				switch(view8[offset]|0) {
				case 0x30: view8[p] = view8[p] |  0; break;
				case 0x31: view8[p] = view8[p] |  1; break;
				case 0x32: view8[p] = view8[p] |  2; break;
				case 0x33: view8[p] = view8[p] |  3; break;
				case 0x34: view8[p] = view8[p] |  4; break;
				case 0x35: view8[p] = view8[p] |  5; break;
				case 0x36: view8[p] = view8[p] |  6; break;
				case 0x37: view8[p] = view8[p] |  7; break;
				case 0x38: view8[p] = view8[p] |  8; break;
				case 0x39: view8[p] = view8[p] |  9; break;
				case 0x61: view8[p] = view8[p] | 10; break;
				case 0x62: view8[p] = view8[p] | 11; break;
				case 0x63: view8[p] = view8[p] | 12; break;
				case 0x64: view8[p] = view8[p] | 13; break;
				case 0x65: view8[p] = view8[p] | 14; break;
				case 0x66: view8[p] = view8[p] | 15; break;
				}
				// Skip the next byte because it's always 0.
				offset = (offset + 2)|0;
			}
			return offset|0;
		}

		return {
			toHex: toHex,
			fromHex: fromHex
		}
	}

	var heap_size = 4096;
	var hex_heap = new ArrayBuffer(heap_size);
	var asm = hexAsm(window, undefined, hex_heap);

	/**
	 * @param {ArrayBuffer} buff
	 * @param {int} [offset]
	 * @param {int} [len]
	 * @returns {string}
	 */
	function toHex(buff, offset, len) {
		offset = offset || 0;
		len = len || buff.byteLength;
		var buff8 = new Uint8Array(buff);
		var heap8 = new Uint8Array(hex_heap);
		var l = len; // save the length for later.
		for(var i = 0 ; len > 0 ; ++i, ++offset, --len) {
			heap8[i] = buff8[offset];
		}
		i = asm.toHex(0, i);
		// l * 2 because the hex string is twice as long as the original byte length.
		return String.fromCharCode.apply(null, new Uint8Array(hex_heap, i, (l * 2)));
	}

	/**
	 * @param {string} str
	 * @returns {ArrayBuffer}
	 */
	function fromHex(str) {
		CS.stringInToArrayBuffer(hex_heap, str);
		var i = asm.fromHex(0, str.length * 2);
		return CS.sliceArrayBuffer(hex_heap, i, Math.ceil(str.length / 2) | 0);
	}

	return {
		toHex: toHex,
		fromHex: fromHex
	}
}();
