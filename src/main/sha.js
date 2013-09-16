/**
 * User: chris
 * Date: 9/13/13
 */

"use strict";

var Sha256 = function(){

	/**
	 * @param {window} stdlib
	 * @param {*} foreign
	 * @param {ArrayBuffer} heap
	 * @returns {{init: Function, hash: Function}}
	 */
	function shaAsm(stdlib, foreign, heap) {
		"use asm";

		var heap8  = new stdlib.Uint8Array(heap);
		var heap32 = new stdlib.Uint32Array(heap);
		/* Compression constants. */
		var K = 0;
		/* Context struct byte offsets. */
		var H0 =  0, H1 =  4, H2 =  8, H3 = 12,
		    H4 = 16, H5 = 20, H6 = 24, H7 = 28,
		    W  = 32;

		function init() {
// Load the K constants table.
heap32[0>>2]=0x428a2f98; heap32[4>>2]=0x71374491; heap32[8>>2]=0xb5c0fbcf; heap32[12>>2]=0xe9b5dba5;
heap32[16>>2]=0x3956c25b; heap32[20>>2]=0x59f111f1; heap32[24>>2]=0x923f82a4; heap32[28>>2]=0xab1c5ed5;
heap32[32>>2]=0xd807aa98; heap32[36>>2]=0x12835b01; heap32[40>>2]=0x243185be; heap32[44>>2]=0x550c7dc3;
heap32[48>>2]=0x72be5d74; heap32[52>>2]=0x80deb1fe; heap32[56>>2]=0x9bdc06a7; heap32[60>>2]=0xc19bf174;
heap32[64>>2]=0xe49b69c1; heap32[68>>2]=0xefbe4786; heap32[72>>2]=0x0fc19dc6; heap32[76>>2]=0x240ca1cc;
heap32[80>>2]=0x2de92c6f; heap32[84>>2]=0x4a7484aa; heap32[88>>2]=0x5cb0a9dc; heap32[92>>2]=0x76f988da;
heap32[96>>2]=0x983e5152; heap32[100>>2]=0xa831c66d; heap32[104>>2]=0xb00327c8; heap32[108>>2]=0xbf597fc7;
heap32[112>>2]=0xc6e00bf3; heap32[116>>2]=0xd5a79147; heap32[120>>2]=0x06ca6351; heap32[124>>2]=0x14292967;
heap32[128>>2]=0x27b70a85; heap32[132>>2]=0x2e1b2138; heap32[136>>2]=0x4d2c6dfc; heap32[140>>2]=0x53380d13;
heap32[144>>2]=0x650a7354; heap32[148>>2]=0x766a0abb; heap32[152>>2]=0x81c2c92e; heap32[156>>2]=0x92722c85;
heap32[160>>2]=0xa2bfe8a1; heap32[164>>2]=0xa81a664b; heap32[168>>2]=0xc24b8b70; heap32[172>>2]=0xc76c51a3;
heap32[176>>2]=0xd192e819; heap32[180>>2]=0xd6990624; heap32[184>>2]=0xf40e3585; heap32[188>>2]=0x106aa070;
heap32[192>>2]=0x19a4c116; heap32[196>>2]=0x1e376c08; heap32[200>>2]=0x2748774c; heap32[204>>2]=0x34b0bcb5;
heap32[208>>2]=0x391c0cb3; heap32[212>>2]=0x4ed8aa4a; heap32[216>>2]=0x5b9cca4f; heap32[220>>2]=0x682e6ff3;
heap32[224>>2]=0x748f82ee; heap32[228>>2]=0x78a5636f; heap32[232>>2]=0x84c87814; heap32[236>>2]=0x8cc70208;
heap32[240>>2]=0x90befffa; heap32[244>>2]=0xa4506ceb; heap32[248>>2]=0xbef9a3f7; heap32[252>>2]=0xc67178f2;
		}

		function rightRotate(word, bits) {
			word = word|0;
			bits = bits|0;
			return ((word << (32 - bits)) | (word >>> bits))|0;
		}

		function rightShift(word, bits) {
			word = word|0;
			bits = bits|0;
			return (word >>> bits)|0;
		}

		/**
		 * @param {int} x
		 * @param {int} y
		 * @param {int} z
		 * @returns {int}
		 */
		function Ch(x, y, z) {
			x = x|0;
			y = y|0;
			z = z|0;
			return (
				(x & y) ^
				((~x) & z)
			)|0;
		}

		/**
		 * @param {int} x
		 * @param {int} y
		 * @param {int} z
		 * @returns {int}
		 */
		function Maj(x, y, z) {
			x = x|0;
			y = y|0;
			z = z|0;
			return (
				(x & y) ^
				(x & z) ^
				(y & z)
			)|0;
		}

		/**
		 * @param {int} x
		 * @return {int}
		 */
		function Σ0(x) {
			x = x|0;
			return (
				rightRotate(x,  2) ^
				rightRotate(x, 13) ^
				rightRotate(x, 22)
			)|0;
		}

		/**
		 * @param {int} x
		 * @return {int}
		 */
		function Σ1(x) {
			x = x|0;
			return (
				rightRotate(x,  6) ^
				rightRotate(x, 11) ^
				rightRotate(x, 25)
			)|0;
		}

		/**
		 * @param {int} x
		 * @return {int}
		 */
		function σ0(x) {
			x = x|0;
			return (
				rightRotate(x,  7) ^
				rightRotate(x, 18) ^
				rightShift (x,  3)
			)|0;
		}

		/**
		 * @param {int} x
		 * @return {int}
		 */
		function σ1(x) {
			x = x|0;
			return (
				rightRotate(x, 17) ^
				rightRotate(x, 19) ^
				rightShift (x, 10)
			)|0;
		}

		/*
		Context {
			h0: 4 bytes:  0 ->  4
			h1: 4 bytes:  4 ->  8
			h2: 4 bytes:  8 -> 12
			h3: 4 bytes: 12 -> 16
			h4: 4 bytes: 16 -> 20
			h5: 4 bytes: 20 -> 24
			h6: 4 bytes: 24 -> 28
			h7: 4 bytes: 28 -> 32
			W : 256 bytes: 32 -> 288
		}
		*/

		function initContext(context) {
			context = context|0;
			heap32[(context + H0) >> 2] = 0x6a09e667;
			heap32[(context + H1) >> 2] = 0xbb67ae85;
			heap32[(context + H2) >> 2] = 0x3c6ef372;
			heap32[(context + H3) >> 2] = 0xa54ff53a;
			heap32[(context + H4) >> 2] = 0x510e527f;
			heap32[(context + H5) >> 2] = 0x9b05688c;
			heap32[(context + H6) >> 2] = 0x1f83d9ab;
			heap32[(context + H7) >> 2] = 0x5be0cd19;
		}

		/**
		 * @param {int} context
		 * @param {int} chunk
		 */
		function hash(context, chunk) {
			context = context|0;
			chunk = chunk|0;
			var i = 0, T1 = 0, T2 = 0;
			var a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0;

			// Prepare the message schedule
			// Copy the chunk to the first 16 words of the schedule
			for( ; (i|0) < 64 ; i = (i + 4)|0) {
				heap32[(context + W + i) >> 2] =
					// Convert to big-endian
					(heap8[(chunk + i + 0)|0] << 24) |
					(heap8[(chunk + i + 1)|0] << 16) |
					(heap8[(chunk + i + 2)|0] <<  8) |
					(heap8[(chunk + i + 3)|0]      )
				;
//				heap32[(context + W + i) >> 2] = heap32[(chunk + i) >> 2];
			}
			// Expand the first 16 words to the rest of the schedule
			for( ; (i|0) < 256 ; i = (i + 4)|0) {
				heap32[(context + W + i) >> 2] = (
					(σ1(heap32[(context + W + (i - ( 2 << 2))) >> 2]|0)|0) +
					(   heap32[(context + W + (i - ( 7 << 2))) >> 2]   |0) +
					(σ0(heap32[(context + W + (i - (15 << 2))) >> 2]|0)|0) +
					(   heap32[(context + W + (i - (16 << 2))) >> 2]   |0)
				)|0;
			}

			// Initialize the working variables with the current hash value.
			a = heap32[(context + H0) >> 2]|0;
			b = heap32[(context + H1) >> 2]|0;
			c = heap32[(context + H2) >> 2]|0;
			d = heap32[(context + H3) >> 2]|0;
			e = heap32[(context + H4) >> 2]|0;
			f = heap32[(context + H5) >> 2]|0;
			g = heap32[(context + H6) >> 2]|0;
			h = heap32[(context + H7) >> 2]|0;

			// Compress the chunk
			for(i = 0 ; (i|0) < 256 ; i = (i + 4)|0) {
				T1 = (
					(h|0) +
					(Σ1(e)|0) +
					(Ch(e, f, g)|0) +
					(heap32[(K + i) >> 2]|0) +
					(heap32[(context + W + i) >> 2]|0)
				)|0;
				T2 = ((Σ0(a)|0) + (Maj(a, b, c)|0))|0;

				// Rotate
				h = g;
				g = f;
				f = e;
				e = (d + T1)|0;
				d = c;
				c = b;
				b = a;
				a = (T1 + T2)|0;
			}

			// Add the compressed chunk to the current hash value.
			heap32[(context + H0) >> 2] = (heap32[(context + H0) >> 2]|0) + (a|0);
			heap32[(context + H1) >> 2] = (heap32[(context + H1) >> 2]|0) + (b|0);
			heap32[(context + H2) >> 2] = (heap32[(context + H2) >> 2]|0) + (c|0);
			heap32[(context + H3) >> 2] = (heap32[(context + H3) >> 2]|0) + (d|0);
			heap32[(context + H4) >> 2] = (heap32[(context + H4) >> 2]|0) + (e|0);
			heap32[(context + H5) >> 2] = (heap32[(context + H5) >> 2]|0) + (f|0);
			heap32[(context + H6) >> 2] = (heap32[(context + H6) >> 2]|0) + (g|0);
			heap32[(context + H7) >> 2] = (heap32[(context + H7) >> 2]|0) + (h|0);
		}

		return {
			init: init,
			initContext: initContext,
			hash: hash
		}
	}

	var heap = new ArrayBuffer(4096);
	var heap8 = new Uint8Array(heap);
	var heap32 = new Uint32Array(heap);
	var asm = shaAsm(window, undefined, heap);
	asm.init();

	/**
	 * @param {ArrayBuffer} buff
	 * @param {int} [offset]
	 * @param {int} [len]
	 * @return {ArrayBuffer}
	 */
	function hash(buff, offset, len) {
		offset = (offset === undefined ? 0 : offset);
		len = (len === undefined ? buff.byteLength : len);
		var i, b, c, buff8 = new Uint8Array(buff);
		var context = 300, chunk = 600;

		asm.initContext(context);

		for(i = 0, b = offset, c = chunk ; i < len ; ) {
			heap8[chunk + (i++)] = buff8[b++];
			if((i % 64) > 0) {
				continue;
			}
			asm.hash(context, chunk);
			i = 0;
		}

		// Append the 0x80 byte
		heap8[chunk + (i++)] = 0x80;

		// Append padding
		while(((i + 8) % 64) > 0) {
			if((i % 64) == 0) {
				asm.hash(context, chunk);
				i = 0;
			}
			heap8[chunk + (i++)] = 0x00;
		}

		// Append the length
		heap32[(chunk + i) >> 2] = 0x00000000;
		i += 4;
		// Length in bits
		len *= 8;
		// Convert to big-endian
		len =
			((len & 0x000000ff) <<  24) |
			((len & 0x0000ff00) <<   8) |
			((len & 0x00ff0000) >>>  8) |
			((len & 0xff000000) >>> 24)
		;
		heap32[(chunk + i) >> 2] = len & 0xffffffff;

		asm.hash(context, chunk);

		buff8 = new Uint8Array(32);
		for(i = 0 ; i < 32 ; i++) {
			buff8[i] = heap8[context + i];
		}

		return buff8.buffer;
	}

	function hashString(str) {
		var buff = new Uint8Array(str.length);
		for(var i = 0 ; i < str.length ; i++) {
			buff[i] = str.charCodeAt(i) & 0xff; // ascii only for now
		}
		return hash(buff.buffer);
	}

	return {
		hash: hash,
		hashString: hashString
	}

}();



function toHex(word) {
	word = word|0;
	var i, hex = "";
	hex += toHex.hexChars[word >>> 28 & 0xf];
	hex += toHex.hexChars[word >>> 24 & 0xf];
	hex += toHex.hexChars[word >>> 20 & 0xf];
	hex += toHex.hexChars[word >>> 16 & 0xf];
	hex += toHex.hexChars[word >>> 12 & 0xf];
	hex += toHex.hexChars[word >>>  8 & 0xf];
	hex += toHex.hexChars[word >>>  4 & 0xf];
	hex += toHex.hexChars[word >>>  0 & 0xf];
	return hex;
}
toHex.hexChars = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
