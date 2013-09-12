/**
 * User: chris
 * Date: 9/2/13
 */

"use strict";

var CS = function() {

	/**
	 * @param {string} str
	 * @return {ArrayBuffer}
	 */
	function stringToArrayBuffer(str) {
		return nStringToArrayBuffer(str, str.length);
		/*var buff = new ArrayBuffer(str.length * 2);
		stringInToArrayBuffer(buff, str);
		return buff;*/
	}

	/**
	 * @param {string} str
	 * @param {int} len
	 * @return {ArrayBuffer}
	 */
	function nStringToArrayBuffer(str, len) {
		var buff = new ArrayBuffer(len * 2);
		nStringInToArrayBuffer(buff, 0, str, 0, len);
		return buff;
	}

	/**
	 * @param {ArrayBuffer} buffer
	 * @param {string} str
	 */
	function stringInToArrayBuffer(buffer, str) {
		nStringInToArrayBuffer(buffer, 0, str, 0, str.length);
		/*var bufferView = new Uint16Array(buffer);
		for(var i = 0 ; i < str.length ; ++i) {
			bufferView[i] = str.charCodeAt(i);
		}*/
	}

	/**
	 * @param {ArrayBuffer} buffer
	 * @param {int} bufferOffset
	 * @param {string} str
	 * @param {int} strOffset
	 * @param {int} len
	 */
	function nStringInToArrayBuffer(buffer, bufferOffset, str, strOffset, len) {
		var i, j, bufferView = new Uint16Array(buffer);
		for(i = strOffset, j = bufferOffset ; i < (strOffset + len) ; i += 1, j += 2) {
			bufferView[j >> 1] = str.charCodeAt(i);
		}
	}

	/**
	 * @param {ArrayBuffer} buffer
	 * @param {int} [offset]
	 * @param {int} [len]
	 * @returns {string}
	 */
	function arrayBufferToString(buffer, offset, len) {
		offset = (offset === undefined ? 0 : offset);
		len = (len === undefined ? buffer.byteLength : len);
		return String.fromCharCode.apply(null, new Uint8Array(buffer, offset, len));
	}

	function arrayBufferInToArrayBuffer(dest, destOffset, src, srcOffset, len) {
		var destView = new Uint8Array(dest);
		var srcView = new Uint8Array(src);
		for(var i = 0 ; i < len ; i++) {
			destView[destOffset++] = srcView[srcOffset++];
		}
	}

	function sliceArrayBuffer(buffer, offset, len) {
		var dest = new ArrayBuffer(len);
		arrayBufferInToArrayBuffer(dest, buffer, offset, len);
		return dest;
	}

	return {
		"stringToArrayBuffer": stringToArrayBuffer,
		"nStringToArrayBuffer": nStringToArrayBuffer,
		"stringInToArrayBuffer": stringInToArrayBuffer,
		"nStringInToArrayBuffer": nStringInToArrayBuffer,
		"arrayBufferToString": arrayBufferToString,
		"arrayBufferInToArrayBuffer": arrayBufferInToArrayBuffer,
		"sliceArrayBuffer": sliceArrayBuffer
	}

}();
