/**
 * User: chris
 * Date: 9/3/13
 */

"use strict";

var Aes = function() {

	/**
	 * @param {window} stdlib
	 * @param {*} foreign
	 * @param {ArrayBuffer} heap
	 * @returns {{encrypt: Function, decrypt: Function}}
	 */
	function aesAsm(stdlib, foreign, heap) {
		"use asm";

		var view8  = new stdlib.Uint8Array(heap);
		var view32 = new stdlib.Uint32Array(heap);
		var Te0  =     0; // 1024b
		var Te1  =  1024;
		var Te2  =  2048;
		var Te3  =  3072;
		var Te4  =  4096;
		var Td0  =  5120;
		var Td1  =  6144;
		var Td2  =  7168;
		var Td3  =  8192;
		var Td4  =  9216;
		var rcon = 10240; // 40b

		/**
		 * Convert 4 bytes to a 32-bit word.
		 * @param {int} bp Byte-pointer to 4 bytes for conversion.
		 * @returns {int} 32-bit word.
		 */
		function btow(bp) {
			bp = bp|0;
			return (
				(view8[(bp    )  ] << 24) ^
				(view8[(bp + 1)|0] << 16) ^
				(view8[(bp + 2)|0] <<  8) ^
				(view8[(bp + 3)|0]      )
			)|0;
		}

		function wtob(bp, word) {
			bp = bp|0;
			word = word|0;
			view8[(bp    )  ] = ((word >> 24) & 0xff)|0;
			view8[(bp + 1)|0] = ((word >> 16) & 0xff)|0;
			view8[(bp + 2)|0] = ((word >>  8) & 0xff)|0;
			view8[(bp + 3)|0] = ((word      ) & 0xff)|0;
		}

		function init() {
			// temporarily stored these thousands of statements in init.js so my IDE
			// isn't slow to analyse the code under active development.
		}

		/*
		 Te0 =     0 | 256*4 = 1024b
		 Te1 =  1024
		 Te2 =  2048
		 Te3 =  3072
		 Te4 =  4096
		 Td0 =  5120
		 Td1 =  6144
		 Td2 =  7168
		 Td3 =  8192
		 Td4 =  9216
		       10240

		 rcon = 10240 | 10*4 = 40b
		        10280

		 rk = 10280 | + 240
		      10520

		 key = 10520 | + 32
		       10552

		 plain = 10552 | 16
		         10568

		 cipher = 10568 | + 16
		          10584
		 */

		/**
		 * @param {int} rk Byte-pointer to the key schedule.
		 * @param {int} key Byte-pointer to the key.
		 * @param {int} [bitLength] Only 256 is supported.
		 * @return {int} The number of rounds needed for the specified bitLength. Pass
		 *               this value into encrypt(rk, nRounds, plain, cipher).
		 */
		function createEncrypt(rk, key, bitLength) {
			rk = rk|0;
			key = key|0;
			bitLength = bitLength|0;
			var i = 0;
			var temp = 0;
			bitLength = 256;

			view32[rk >> 2] = btow(key)|0; // 0
			view32[(rk +  4) >> 2] = btow((key +  4)|0)|0; // 1
			view32[(rk +  8) >> 2] = btow((key +  8)|0)|0; // 2
			view32[(rk + 12) >> 2] = btow((key + 12)|0)|0; // 3
			/* <-- 128-bit key would go here --> */
			view32[(rk + 16) >> 2] = btow((key + 16)|0)|0; // 4
			view32[(rk + 20) >> 2] = btow((key + 20)|0)|0; // 5
			/* <-- 192-bit key would go here --> */
			view32[(rk + 24) >> 2] = btow((key + 24)|0)|0; // 6
			view32[(rk + 28) >> 2] = btow((key + 28)|0)|0; // 7
			if((bitLength|0) == 256) {
				for(;;) {
					temp = view32[(rk + 28) >> 2]|0;

					view32[(rk + 32) >> 2] = ( // 8
						(view32[rk >> 2]) ^
						(view32[(Te4 + ((temp >> 16) & 0xff)) >> 2] & 0xff000000) ^
						(view32[(Te4 + ((temp >>  8) & 0xff)) >> 2] & 0x00ff0000) ^
						(view32[(Te4 + ((temp      ) & 0xff)) >> 2] & 0x0000ff00) ^
						(view32[(Te4 + ((temp >> 24)       )) >> 2] & 0x000000ff)
					)|0;

					view32[(rk + 36) >> 2] = (view32[(rk +  4) >> 2] ^ view32[((rk + 32)|0) >> 2])|0; // 9
					view32[(rk + 40) >> 2] = (view32[(rk +  8) >> 2] ^ view32[((rk + 36)|0) >> 2])|0; // 10
					view32[(rk + 44) >> 2] = (view32[(rk + 12) >> 2] ^ view32[((rk + 40)|0) >> 2])|0; // 11

					i = (i + 1)|0;
					if((i|0) == 7) {
						return 14;
					}

					temp = view32[(rk + 44) >> 2]|0;
					view32[(rk + 48) >> 2] = ( // 12
						(view32[(rk + 16) >> 2]) ^
						(view32[(Te4 + ((temp >> 24)       )) >> 2] & 0xff000000) ^
						(view32[(Te4 + ((temp >> 16) & 0xff)) >> 2] & 0x00ff0000) ^
						(view32[(Te4 + ((temp >>  8) & 0xff)) >> 2] & 0x0000ff00) ^
						(view32[(Te4 + ((temp      ) & 0xff)) >> 2] & 0x000000ff)
					)|0;

					view32[(rk + 52) >> 2] = (view32[(rk + 20) >> 2] ^ view32[(rk + 48) >> 2])|0; // 13
					view32[(rk + 56) >> 2] = (view32[(rk + 24) >> 2] ^ view32[(rk + 52) >> 2])|0; // 14
					view32[(rk + 60) >> 2] = (view32[(rk + 28) >> 2] ^ view32[(rk + 56) >> 2])|0; // 15

					rk = 32;
				}
			}
			return 0;
		}

		/**
		 * @param {int} rk Byte-pointer to the key schedule.
		 * @param {int} key Byte-pointer to the key.
		 * @param {int} [bitLength] Only 256 is supported.
		 * @return {int} The number of rounds needed for the specified bitLength. Pass
		 *               this value into encrypt(rk, nRounds, cipher, plain).
		 */
		function createDecrypt(rk, key, bitLength) {
			rk = rk|0;
			key = key|0;
			bitLength = bitLength|0;
			return 0;
		}

		/**
		 * @param {int} rk Byte-pointer to the key schedule.
		 * @param {int} nRounds The number of rounds needed for the key schedules bit length.
		 * @param {int} plain Byte-pointer to 16 bytes of plaintext.
		 * @param {int} cipher Byte-pointer to 16 bytes of ciphertext.
		 */
		function encrypt(rk, nRounds, plain, cipher) {
			rk = rk|0;
			nRounds = nRounds|0;
			plain = plain|0;
			cipher = cipher|0;
			var s0 = 0, s1 = 0, s2 = 0, s3 = 0, t0 = 0, t1 = 0, t2 = 0, t3 = 0, r = 0;

			// Copy the plaintext to the cipher state and apply the initial round key
			s0 = btow((plain     )  ) ^ view32[(rk     ) >> 2];
			s1 = btow((plain +  4)|0) ^ view32[(rk +  4) >> 2];
			s2 = btow((plain +  8)|0) ^ view32[(rk +  8) >> 2];
			s3 = btow((plain + 12)|0) ^ view32[(rk + 12) >> 2];

			// TODO Unroll the loop
			// Use a loop to apply the rounds
			r = nRounds >> 1;
			for( ; ; ) {
				t0 =
					(view32[(Te0 + ((s0 >> 24)       )) >> 2]) ^
					(view32[(Te1 + ((s1 >> 16) & 0xff)) >> 2]) ^
					(view32[(Te2 + ((s2 >>  8) & 0xff)) >> 2]) ^
					(view32[(Te3 + ((s3      ) & 0xff)) >> 2]) ^
					(view32[(rk + 16) >> 2]);

				t1 =
					(view32[(Te0 + ((s1 >> 24)       )) >> 2]) ^
					(view32[(Te1 + ((s2 >> 16) & 0xff)) >> 2]) ^
					(view32[(Te2 + ((s3 >>  8) & 0xff)) >> 2]) ^
					(view32[(Te3 + ((s0      ) & 0xff)) >> 2]) ^
					(view32[(rk + 20) >> 2]);

				t2 =
					(view32[(Te0 + ((s2 >> 24)       )) >> 2]) ^
					(view32[(Te1 + ((s3 >> 16) & 0xff)) >> 2]) ^
					(view32[(Te2 + ((s0 >>  8) & 0xff)) >> 2]) ^
					(view32[(Te3 + ((s1      ) & 0xff)) >> 2]) ^
					(view32[(rk + 24) >> 2]);

				t3 =
					(view32[(Te0 + ((s3 >> 24)       )) >> 2]) ^
					(view32[(Te1 + ((s0 >> 16) & 0xff)) >> 2]) ^
					(view32[(Te2 + ((s1 >>  8) & 0xff)) >> 2]) ^
					(view32[(Te3 + ((s2      ) & 0xff)) >> 2]) ^
					(view32[(rk + 28) >> 2]);

				rk = (rk + 32)|0;
				r = (r - 1)|0;
				if((r|0) == 0) {
					break;
				}

				s0 =
					(view32[(Te0 + ((t0 >> 24)       )) >> 2]) ^
					(view32[(Te1 + ((t1 >> 16) & 0xff)) >> 2]) ^
					(view32[(Te2 + ((t2 >>  8) & 0xff)) >> 2]) ^
					(view32[(Te3 + ((t3      ) & 0xff)) >> 2]) ^
					(view32[(rk     ) >> 2]);

				s1 =
					(view32[(Te0 + ((t1 >> 24)       )) >> 2]) ^
					(view32[(Te1 + ((t2 >> 16) & 0xff)) >> 2]) ^
					(view32[(Te2 + ((t3 >>  8) & 0xff)) >> 2]) ^
					(view32[(Te3 + ((t0      ) & 0xff)) >> 2]) ^
					(view32[(rk +  4) >> 2]);

				s2 =
					(view32[(Te0 + ((t2 >> 24)       )) >> 2]) ^
					(view32[(Te1 + ((t3 >> 16) & 0xff)) >> 2]) ^
					(view32[(Te2 + ((t0 >>  8) & 0xff)) >> 2]) ^
					(view32[(Te3 + ((t1      ) & 0xff)) >> 2]) ^
					(view32[(rk +  8) >> 2]);

				s3 =
					(view32[(Te0 + ((t3 >> 24)       )) >> 2]) ^
					(view32[(Te1 + ((t0 >> 16) & 0xff)) >> 2]) ^
					(view32[(Te2 + ((t1 >>  8) & 0xff)) >> 2]) ^
					(view32[(Te3 + ((t2      ) & 0xff)) >> 2]) ^
					(view32[(rk + 12) >> 2]);
			}

			// Apply the last round and copy the cipher state into the ciphertext.
			s0 =
				(view32[(Te4 + ((t0 >> 24)       )) >> 2] & 0xff000000) ^
				(view32[(Te4 + ((t1 >> 16) & 0xff)) >> 2] & 0x00ff0000) ^
				(view32[(Te4 + ((t2 >>  8) & 0xff)) >> 2] & 0x0000ff00) ^
				(view32[(Te4 + ((t3      ) & 0xff)) >> 2] & 0x000000ff) ^
				(view32[(rk     ) >> 2]);
			wtob((cipher     )|0, s0);

			s1 =
				(view32[(Te4 + ((t1 >> 24)       )) >> 2] & 0xff000000) ^
				(view32[(Te4 + ((t2 >> 16) & 0xff)) >> 2] & 0x00ff0000) ^
				(view32[(Te4 + ((t3 >>  8) & 0xff)) >> 2] & 0x0000ff00) ^
				(view32[(Te4 + ((t0      ) & 0xff)) >> 2] & 0x000000ff) ^
				(view32[(rk +  4) >> 2]);
			wtob((cipher +  4)|0, s1);

			s2 =
				(view32[(Te4 + ((t2 >> 24)       )) >> 2] & 0xff000000) ^
				(view32[(Te4 + ((t3 >> 16) & 0xff)) >> 2] & 0x00ff0000) ^
				(view32[(Te4 + ((t0 >>  8) & 0xff)) >> 2] & 0x0000ff00) ^
				(view32[(Te4 + ((t1      ) & 0xff)) >> 2] & 0x000000ff) ^
				(view32[(rk +  8) >> 2]);
			wtob((cipher +  8)|0, s2);

			s3 =
				(view32[(Te4 + ((t3 >> 24)       )) >> 2] & 0xff000000) ^
				(view32[(Te4 + ((t0 >> 16) & 0xff)) >> 2] & 0x00ff0000) ^
				(view32[(Te4 + ((t1 >>  8) & 0xff)) >> 2] & 0x0000ff00) ^
				(view32[(Te4 + ((t2      ) & 0xff)) >> 2] & 0x000000ff) ^
				(view32[(rk + 12) >> 2]);
			wtob((cipher + 12)|0, s3);
		}

		function decrypt(rk, nRounds, cipher, plain) {
			rk = rk|0;
			nRounds = nRounds|0;
			cipher = cipher|0;
			plain = plain|0;
		}

		return {
			init: init,
			createEncrypt: createEncrypt,
			createDecrypt: createDecrypt,
			encrypt:encrypt,
			decrypt: decrypt
		}
	}

	const heapSize = 16384; // 2^14
	const rkOffset = 10280; // 240b
	const keyOffset = 10520; // 32b
	const plainOffset = 10552; // 16b
	const cipherOffset = 10568; // 16b

	var aesHeap = new ArrayBuffer(heapSize);
	var aesHeap8 = new Uint8Array(aesHeap);
	var asm = aesAsm(window, undefined, aesHeap);
	asm.init();


	function encrypt(password, data) {
		// TODO Create a real key from the password.
		for(var i = 0 ; i < 32 ; i++) {
			aesHeap8[keyOffset + i] = 65 + i;
		}
		var nRounds = asm.createEncrypt(rkOffset, keyOffset);
		// TODO process data 16 bytes (8 characters) at a time.
		// TODO copy data into the plaintext buffer.
		asm.encrypt(rkOffset, nRounds, plainOffset, cipherOffset);
		// TODO copy the ciphertext buffer to an ArrayBuffer.
		return "";
	}

	function decrypt(password, data) {
		// TODO Create a real key from the password.
		for(var i = 0 ; i < 32 ; i++) {
			aesHeap8[keyOffset + i] = 65 + i;
		}
		var nRounds = asm.createDecrypt(rkOffset, keyOffset);
		// TODO process data 16 bytes (8 characters) at a time.
		// TODO copy data into the ciphertext buffer.
		asm.decrypt(rkOffset, nRounds, cipherOffset, plainOffset);
		// TODO copy the plaintext buffer to a string.
		return "";
	}

	return {
		"encrypt": encrypt,
		"decrypt": decrypt
	}

}();
