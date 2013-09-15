/**
 * User: chris
 * Date: 9/13/13
 */

"use strict";

var h0 = 0x6a09e667,
    h1 = 0xbb67ae85,
    h2 = 0x3c6ef372,
    h3 = 0xa54ff53a,
    h4 = 0x510e527f,
    h5 = 0x9b05688c,
    h6 = 0x1f83d9ab,
    h7 = 0x5be0cd19;

var k = [
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

var heap = new ArrayBuffer(4096);
var heap8 = new Uint8Array(heap);
var heap16 = new Uint16Array(heap);
var heap32 = new Uint32Array(heap);

/*
HashContext {
	h0: 4 bytes:  0 ->  4
	h1: 4 bytes:  4 ->  8
	h2: 4 bytes:  8 -> 12
	h3: 4 bytes: 12 -> 16
	h4: 4 bytes: 16 -> 20
	h5: 4 bytes: 20 -> 24
	h6: 4 bytes: 24 -> 28
	h7: 4 bytes: 28 -> 32
	w : 256 bytes: 32 -> 288
}
 */
function HashContext() {
	this.H0 = h0;
	this.H1 = h1;
	this.H2 = h2;
	this.H3 = h3;
	this.H4 = h4;
	this.H5 = h5;
	this.H6 = h6;
	this.H7 = h7;
}

function initHash(context) {
	context = context|0;
	heap32[(context +  0) >>> 2] = h0;
	heap32[(context +  4) >>> 2] = h1;
	heap32[(context +  8) >>> 2] = h2;
	heap32[(context + 12) >>> 2] = h3;
	heap32[(context + 16) >>> 2] = h4;
	heap32[(context + 20) >>> 2] = h5;
	heap32[(context + 24) >>> 2] = h6;
	heap32[(context + 28) >>> 2] = h7;
}

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

function finish(context) {
	//context = context|0;
	var hex = "";
	hex += toHex(context.H0);
	hex += toHex(context.H1);
	hex += toHex(context.H2);
	hex += toHex(context.H3);
	hex += toHex(context.H4);
	hex += toHex(context.H5);
	hex += toHex(context.H6);
	hex += toHex(context.H7);
	/*var i, hex = "";
	for(i = 0 ; i < 8 ; i++) {
		hex += toHex(heap32[(context >> 2) + i]);
	}*/
	return hex;
}

function rightRotate(word, bits) {
	word = word|0;
	bits = bits|0;
	return ((word << (32 - bits)) | (word >>> bits));
}

function rightShift(word, bits) {
	word = word|0;
	bits = bits|0;
	return (word >>> bits);
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
	) >>> 0;
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
	) >>> 0;
}

/**
 * @param {int} word
 * @return {int}
 */
function Σ0(word) {
	word = word|0;
	return (
		rightRotate(word,  2) ^
		rightRotate(word, 13) ^
		rightRotate(word, 22)
	) >>> 0;
}

/**
 * @param {int} word
 * @return {int}
 */
function Σ1(word) {
	word = word|0;
	return (
		rightRotate(word,  6) ^
		rightRotate(word, 11) ^
		rightRotate(word, 25)
	) >>> 0;
}

/**
 * @param {int} word
 * @return {int}
 */
function σ0(word) {
	word = word|0;
	return (
		rightRotate(word,  7) ^
		rightRotate(word, 18) ^
		rightShift (word,  3)
	) >>> 0;
}

/**
 * @param {int} word
 * @return {int}
 */
function σ1(word) {
	word = word|0;
	return (
		rightRotate(word, 17) ^
		rightRotate(word, 19) ^
		rightShift (word, 10)
	) >>> 0;
}

/**
 * @param {HashContext} context
 * @param {Array} chunk
 */
function hash(context, chunk) {
	/*context = context|0;
	chunk = chunk|0;*/
	var i, s0, s1, ch, maj, temp1, temp2, a, b, c, d, e, f, g, h;
	var W = new Array(64); // message schedule
	var T1, T2;

	// Copy the first 16 words of the chunk into the schedule.
	for(i = 0 ; i < 16 ; i++) { // i is a byte-pointer
		W[i] = chunk[i];
//		heap32[(context + 32 + i) >> 2] = heap32[(chunk + (i<<2)) >>> 2];
	}

	// Extend the first 16 words into the remaining 48 words of the schedule.
	for(i = 16 ; i < 64 ; i++) { // i is a byte-pointer
		W[i] = σ1(W[i-2]) + W[i-7] + σ0(i-15) + W[i-16];
		/*s0 =
			(rightRotate(heap32[(context + 32 + i - (15 << 2)) >> 2],  7) ^
			 rightRotate(heap32[(context + 32 + i - (15 << 2)) >> 2], 18) ^
			 rightShift (heap32[(context + 32 + i - (15 << 2)) >> 2],  3)) >>> 0;

		s1 =
			(rightRotate(heap32[(context + 32 + i - ( 2 << 2)) >> 2], 17) ^
			 rightRotate(heap32[(context + 32 + i - ( 2 << 2)) >> 2], 19) ^
			 rightShift (heap32[(context + 32 + i - ( 2 << 2)) >> 2], 10)) >>> 0;

		heap32[(context + 32 + i) >> 2] =
			(heap32[(context + 32 + i - (16 << 2)) >> 2] >>> 0) +
			(s0 >>> 0) +
			(heap32[(context + 32 + i - ( 7 << 2)) >> 2] >>> 0) +
			(s1 >>> 0); // modulo 2^32 ?*/
	}

	// Initialize working variables to the current hash value.
	a = context.H0;
	b = context.H1;
	c = context.H2;
	d = context.H3;
	e = context.H4;
	f = context.H5;
	g = context.H6;
	h = context.H7;
	/*a = heap32[(context +  0) >> 2];
	b = heap32[(context +  4) >> 2];
	c = heap32[(context +  8) >> 2];
	d = heap32[(context + 12) >> 2];
	e = heap32[(context + 16) >> 2];
	f = heap32[(context + 20) >> 2];
	g = heap32[(context + 24) >> 2];
	h = heap32[(context + 28) >> 2];*/

	// Compress the chunk
	for(i = 0 ; i < 64 ; i++) { // i is a word-pointer
		T1 = h + Σ1(e) + Ch(e, f, g) + k[i] + W[i];
		T2 = Σ0(a) + Maj(a, b, c);
		/*s1 = (rightRotate(e,  6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) >>> 0;
		ch = ((e & f) ^ ((~e) & g)) >>> 0;
		temp1 =
			(h + s1 + ch +
			(k[i] >>> 0) + heap32[(context + 32 + (i << 2)) >> 2]) >>> 0; // modulo 2^32 ?
		s0 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) >>> 0;
		maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
		temp2 = (s0 + maj) >>> 0; // modulo 2^32 ?*/

		// Rotate
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	// Add the compressed chunk to the current hash value.
	context.H0 = a + context.H0;
	context.H1 = b + context.H1;
	context.H2 = c + context.H2;
	context.H3 = d + context.H3;
	context.H4 = e + context.H4;
	context.H5 = f + context.H5;
	context.H6 = g + context.H6;
	context.H7 = h + context.H7;
	/*heap32[(context +  0) >> 2] = a + heap32[(context +  0) >> 2];
	heap32[(context +  4) >> 2] = b + heap32[(context +  4) >> 2];
	heap32[(context +  8) >> 2] = c + heap32[(context +  8) >> 2];
	heap32[(context + 12) >> 2] = d + heap32[(context + 12) >> 2];
	heap32[(context + 16) >> 2] = e + heap32[(context + 16) >> 2];
	heap32[(context + 20) >> 2] = f + heap32[(context + 20) >> 2];
	heap32[(context + 24) >> 2] = g + heap32[(context + 24) >> 2];
	heap32[(context + 28) >> 2] = h + heap32[(context + 28) >> 2];*/
	/*heap32[(context +  0) >> 2] = (heap32[(context +  0) >> 2] >>> 0) + (a >>> 0);
	heap32[(context +  4) >> 2] = (heap32[(context +  4) >> 2] >>> 0) + (b >>> 0);
	heap32[(context +  8) >> 2] = (heap32[(context +  8) >> 2] >>> 0) + (c >>> 0);
	heap32[(context + 12) >> 2] = (heap32[(context + 12) >> 2] >>> 0) + (d >>> 0);
	heap32[(context + 16) >> 2] = (heap32[(context + 16) >> 2] >>> 0) + (e >>> 0);
	heap32[(context + 20) >> 2] = (heap32[(context + 20) >> 2] >>> 0) + (f >>> 0);
	heap32[(context + 24) >> 2] = (heap32[(context + 24) >> 2] >>> 0) + (g >>> 0);
	heap32[(context + 28) >> 2] = (heap32[(context + 28) >> 2] >>> 0) + (h >>> 0);*/
}

function hashString(str) {
//	var byteLen = str.length * 2 + 9; // 2 bytes per character + 0x80 byte + 8-byte length
//	var pad = 64 - (byteLen % 64);
	var context = new HashContext();
//	var chunk = 300;
	var chunk = new Array(64);
	var s, c;

	//initHash(context);

	// Copy the string into the chunk
	for(s = 0, c = 0 ; s < str.length ; ) {
		chunk[c++] = str.charCodeAt(s++) & 0xff; // only ascii for now
		if((c % 64) > 0) {
			continue;
		}
		/*for(var i = 0, j = 0 ; i < 64 ; i += 4, j++) {
			chunk[j] =
				((chunk[i + 0] << 24) |
				(chunk[i + 1] << 16) |
				(chunk[i + 2] <<  8) |
				(chunk[i + 3] <<  0)) >>> 0;
		}*/
		hash(context, chunk);
		c = 0;
	}
	/*for(s = 0, c = 0 ; s < str.length ; ) {
		heap8[chunk + c++] = (str.charCodeAt(s++) & 0xff); // only ascii for now
		if((c % 64) > 0) {
			continue;
		}

		hash(context, chunk);
		c = 0;
	}*/

	// Convert the chunk pointer to a byte-pointer
	//b = b << 1;

	// Append the 0x80 byte
	chunk[c++] = 0x80;
	//heap8[chunk + c++] = 0x80;

	// Append padding
	while(((c + 8) % 64) > 0) {
		chunk[c++] = 0x00;
	}
	/*while(((c + 8) % 64) > 0) { // 64(total) - 8(length) = 56
		heap8[chunk + c++] = 0x00;
	}*/

	for(var i = 0, j = 0 ; i < 64 ; i += 4, j++) {
		chunk[j] =
			((chunk[i + 0] << 24) |
			( chunk[i + 1] << 16) |
			( chunk[i + 2] <<  8) |
			( chunk[i + 3] <<  0)) >>> 0;
	}

	// Append length
	chunk[14] = 0x00000000;
	chunk[15] = (str.length * 8) >>> 0;
	/*c = (chunk + c) >> 2; // word-pointer
	heap32[c++] = 0x00;
	heap32[c] = (str.length * 8) >>> 0; // size in bits*/

	// Hash the padded chunk
	hash(context, chunk);

	return finish(context);
}
