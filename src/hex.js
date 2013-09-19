/**
 * User: Chris Steinhoff
 * Date: 9/2/13
 */

"use strict";

(function(window) {
	var hexChars = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
	var revHexChars = new Array(0x66);
	for(var i = 0x30, j = 0; i < 0x3a; i++, j++) {
		revHexChars[i] = j;
	}
	for(i = 0x41; i < 0x47; i++, j++) {
		revHexChars[i] = j;
	}
	for(i = 0x61, j = 10; i < 0x67; i++, j++) {
		revHexChars[i] = j;
	}

	/**
	 * @param {int} bite
	 * @returns {string}
	 */
	window.byteToHex = function(bite) {
		return (
			hexChars[(bite >>> 4) & 0xf] +
			hexChars[(bite >>> 0) & 0xf]
		);
	};

	/**
	 * @param {int} half
	 * @returns {string}
	 */
	window.shortToHex = function(half) {
		return (
			hexChars[(half >>> 12) & 0xf] +
			hexChars[(half >>>  8) & 0xf] +
			hexChars[(half >>>  4) & 0xf] +
			hexChars[(half >>>  0) & 0xf]
		);
	};

	/**
	 * @param {int} word
	 * @returns {string}
	 */
	window.wordToHex = function(word) {
		return (
			hexChars[(word >>> 28) & 0xf] +
			hexChars[(word >>> 24) & 0xf] +
			hexChars[(word >>> 20) & 0xf] +
			hexChars[(word >>> 16) & 0xf] +
			hexChars[(word >>> 12) & 0xf] +
			hexChars[(word >>>  8) & 0xf] +
			hexChars[(word >>>  4) & 0xf] +
			hexChars[(word >>>  0) & 0xf]
		);
	};

	/**
	 * @param {ArrayBuffer} array
	 * @param {int} [offset]
	 * @param {int} [len]
	 * @returns {string}
	 */
	window.arrayToHex = function(array, offset, len) {
		if(!array) {
			return "";
		}
		offset = ((offset === undefined) ? 0 : offset) | 0;
		len = ((len === undefined) ? array.byteLength : len) | 0;
		var array8 = new Uint8Array(array, offset, len);
		var hex = "";
		for(var i = 0; i < len; i++) {
			hex +=
				hexChars[(array8[i] >>> 4) & 0xf] +
				hexChars[(array8[i] >>> 0) & 0xf];
		}
		return hex;
	};

	/**
	 * @param {string} hex
	 * @returns {number}
	 */
	window.intFromHex = function(hex) {
		if(!hex) {
			return 0;
		}
		var num = 0;
		for(var i = 0; i < hex.length; i++) {
			num = (num << 4) ^ (revHexChars[hex.charCodeAt(i) & 0xff])
		}
		return num;
	};

	/**
	 * @param {string} hex
	 * @returns {ArrayBuffer}
	 */
	window.arrayFromHex = function(hex) {
		if(!hex) {
			return new ArrayBuffer(0);
		}
		if((hex.length % 2) != 0) {
			hex = "0" + hex;
		}
		var array = new Uint8Array(hex.length / 2);
		for(var i = 0, j = 0; i < hex.length; j++) {
			array[j] =
				(revHexChars[hex.charCodeAt(i++) & 0xff] << 4) ^
				(revHexChars[hex.charCodeAt(i++) & 0xff]);
		}
		return array.buffer;
	};

})(window);
