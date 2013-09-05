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
		var buff = new ArrayBuffer(str.length * 2);
		stringInToArrayBuffer(buff, str);
		return buff;
	}

	/**
	 * @param {ArrayBuffer} buffer
	 * @param {string} str
	 */
	function stringInToArrayBuffer(buffer, str) {
		var bufferView = new Uint16Array(buffer);
		for(var i = 0 ; i < str.length ; ++i) {
			bufferView[i] = str.charCodeAt(i);
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

	function arrayBufferInToArrayBuffer(dest, src, offset, len) {
		var destView = new Uint8Array(dest);
		var srcView = new Uint8Array(src);
		for(var i = 0 ; i < len ; ) {
			destView[i++] = srcView[offset++];
		}
	}

	function sliceArrayBuffer(buffer, offset, len) {
		var dest = new ArrayBuffer(len);
		arrayBufferInToArrayBuffer(dest, buffer, offset, len);
		return dest;
	}

	return {
		"stringToArrayBuffer": stringToArrayBuffer,
		"stringInToArrayBuffer": stringInToArrayBuffer,
		"arrayBufferToString": arrayBufferToString,
		"arrayBufferInToArrayBuffer": arrayBufferInToArrayBuffer,
		"sliceArrayBuffer": sliceArrayBuffer
	}

}();
