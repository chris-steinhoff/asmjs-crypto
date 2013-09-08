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
				(view8[(bp + 3)|0] << 24) ^
				(view8[(bp + 2)|0] << 16) ^
				(view8[(bp + 1)|0] <<  8) ^
				(view8[(bp    )  ]      )
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
// Load the Te4 lookup table
view32[4096>>2]=0x63636363; view32[4100>>2]=0x7c7c7c7c; view32[4104>>2]=0x77777777; view32[4108>>2]=0x7b7b7b7b;
view32[4112>>2]=0xf2f2f2f2; view32[4116>>2]=0x6b6b6b6b; view32[4120>>2]=0x6f6f6f6f; view32[4124>>2]=0xc5c5c5c5;
view32[4128>>2]=0x30303030; view32[4132>>2]=0x01010101; view32[4136>>2]=0x67676767; view32[4140>>2]=0x2b2b2b2b;
view32[4144>>2]=0xfefefefe; view32[4148>>2]=0xd7d7d7d7; view32[4152>>2]=0xabababab; view32[4156>>2]=0x76767676;
view32[4160>>2]=0xcacacaca; view32[4164>>2]=0x82828282; view32[4168>>2]=0xc9c9c9c9; view32[4172>>2]=0x7d7d7d7d;
view32[4176>>2]=0xfafafafa; view32[4180>>2]=0x59595959; view32[4184>>2]=0x47474747; view32[4188>>2]=0xf0f0f0f0;
view32[4192>>2]=0xadadadad; view32[4196>>2]=0xd4d4d4d4; view32[4200>>2]=0xa2a2a2a2; view32[4204>>2]=0xafafafaf;
view32[4208>>2]=0x9c9c9c9c; view32[4212>>2]=0xa4a4a4a4; view32[4216>>2]=0x72727272; view32[4220>>2]=0xc0c0c0c0;
view32[4224>>2]=0xb7b7b7b7; view32[4228>>2]=0xfdfdfdfd; view32[4232>>2]=0x93939393; view32[4236>>2]=0x26262626;
view32[4240>>2]=0x36363636; view32[4244>>2]=0x3f3f3f3f; view32[4248>>2]=0xf7f7f7f7; view32[4252>>2]=0xcccccccc;
view32[4256>>2]=0x34343434; view32[4260>>2]=0xa5a5a5a5; view32[4264>>2]=0xe5e5e5e5; view32[4268>>2]=0xf1f1f1f1;
view32[4272>>2]=0x71717171; view32[4276>>2]=0xd8d8d8d8; view32[4280>>2]=0x31313131; view32[4284>>2]=0x15151515;
view32[4288>>2]=0x04040404; view32[4292>>2]=0xc7c7c7c7; view32[4296>>2]=0x23232323; view32[4300>>2]=0xc3c3c3c3;
view32[4304>>2]=0x18181818; view32[4308>>2]=0x96969696; view32[4312>>2]=0x05050505; view32[4316>>2]=0x9a9a9a9a;
view32[4320>>2]=0x07070707; view32[4324>>2]=0x12121212; view32[4328>>2]=0x80808080; view32[4332>>2]=0xe2e2e2e2;
view32[4336>>2]=0xebebebeb; view32[4340>>2]=0x27272727; view32[4344>>2]=0xb2b2b2b2; view32[4348>>2]=0x75757575;
view32[4352>>2]=0x09090909; view32[4356>>2]=0x83838383; view32[4360>>2]=0x2c2c2c2c; view32[4364>>2]=0x1a1a1a1a;
view32[4368>>2]=0x1b1b1b1b; view32[4372>>2]=0x6e6e6e6e; view32[4376>>2]=0x5a5a5a5a; view32[4380>>2]=0xa0a0a0a0;
view32[4384>>2]=0x52525252; view32[4388>>2]=0x3b3b3b3b; view32[4392>>2]=0xd6d6d6d6; view32[4396>>2]=0xb3b3b3b3;
view32[4400>>2]=0x29292929; view32[4404>>2]=0xe3e3e3e3; view32[4408>>2]=0x2f2f2f2f; view32[4412>>2]=0x84848484;
view32[4416>>2]=0x53535353; view32[4420>>2]=0xd1d1d1d1; view32[4424>>2]=0x00000000; view32[4428>>2]=0xedededed;
view32[4432>>2]=0x20202020; view32[4436>>2]=0xfcfcfcfc; view32[4440>>2]=0xb1b1b1b1; view32[4444>>2]=0x5b5b5b5b;
view32[4448>>2]=0x6a6a6a6a; view32[4452>>2]=0xcbcbcbcb; view32[4456>>2]=0xbebebebe; view32[4460>>2]=0x39393939;
view32[4464>>2]=0x4a4a4a4a; view32[4468>>2]=0x4c4c4c4c; view32[4472>>2]=0x58585858; view32[4476>>2]=0xcfcfcfcf;
view32[4480>>2]=0xd0d0d0d0; view32[4484>>2]=0xefefefef; view32[4488>>2]=0xaaaaaaaa; view32[4492>>2]=0xfbfbfbfb;
view32[4496>>2]=0x43434343; view32[4500>>2]=0x4d4d4d4d; view32[4504>>2]=0x33333333; view32[4508>>2]=0x85858585;
view32[4512>>2]=0x45454545; view32[4516>>2]=0xf9f9f9f9; view32[4520>>2]=0x02020202; view32[4524>>2]=0x7f7f7f7f;
view32[4528>>2]=0x50505050; view32[4532>>2]=0x3c3c3c3c; view32[4536>>2]=0x9f9f9f9f; view32[4540>>2]=0xa8a8a8a8;
view32[4544>>2]=0x51515151; view32[4548>>2]=0xa3a3a3a3; view32[4552>>2]=0x40404040; view32[4556>>2]=0x8f8f8f8f;
view32[4560>>2]=0x92929292; view32[4564>>2]=0x9d9d9d9d; view32[4568>>2]=0x38383838; view32[4572>>2]=0xf5f5f5f5;
view32[4576>>2]=0xbcbcbcbc; view32[4580>>2]=0xb6b6b6b6; view32[4584>>2]=0xdadadada; view32[4588>>2]=0x21212121;
view32[4592>>2]=0x10101010; view32[4596>>2]=0xffffffff; view32[4600>>2]=0xf3f3f3f3; view32[4604>>2]=0xd2d2d2d2;
view32[4608>>2]=0xcdcdcdcd; view32[4612>>2]=0x0c0c0c0c; view32[4616>>2]=0x13131313; view32[4620>>2]=0xecececec;
view32[4624>>2]=0x5f5f5f5f; view32[4628>>2]=0x97979797; view32[4632>>2]=0x44444444; view32[4636>>2]=0x17171717;
view32[4640>>2]=0xc4c4c4c4; view32[4644>>2]=0xa7a7a7a7; view32[4648>>2]=0x7e7e7e7e; view32[4652>>2]=0x3d3d3d3d;
view32[4656>>2]=0x64646464; view32[4660>>2]=0x5d5d5d5d; view32[4664>>2]=0x19191919; view32[4668>>2]=0x73737373;
view32[4672>>2]=0x60606060; view32[4676>>2]=0x81818181; view32[4680>>2]=0x4f4f4f4f; view32[4684>>2]=0xdcdcdcdc;
view32[4688>>2]=0x22222222; view32[4692>>2]=0x2a2a2a2a; view32[4696>>2]=0x90909090; view32[4700>>2]=0x88888888;
view32[4704>>2]=0x46464646; view32[4708>>2]=0xeeeeeeee; view32[4712>>2]=0xb8b8b8b8; view32[4716>>2]=0x14141414;
view32[4720>>2]=0xdededede; view32[4724>>2]=0x5e5e5e5e; view32[4728>>2]=0x0b0b0b0b; view32[4732>>2]=0xdbdbdbdb;
view32[4736>>2]=0xe0e0e0e0; view32[4740>>2]=0x32323232; view32[4744>>2]=0x3a3a3a3a; view32[4748>>2]=0x0a0a0a0a;
view32[4752>>2]=0x49494949; view32[4756>>2]=0x06060606; view32[4760>>2]=0x24242424; view32[4764>>2]=0x5c5c5c5c;
view32[4768>>2]=0xc2c2c2c2; view32[4772>>2]=0xd3d3d3d3; view32[4776>>2]=0xacacacac; view32[4780>>2]=0x62626262;
view32[4784>>2]=0x91919191; view32[4788>>2]=0x95959595; view32[4792>>2]=0xe4e4e4e4; view32[4796>>2]=0x79797979;
view32[4800>>2]=0xe7e7e7e7; view32[4804>>2]=0xc8c8c8c8; view32[4808>>2]=0x37373737; view32[4812>>2]=0x6d6d6d6d;
view32[4816>>2]=0x8d8d8d8d; view32[4820>>2]=0xd5d5d5d5; view32[4824>>2]=0x4e4e4e4e; view32[4828>>2]=0xa9a9a9a9;
view32[4832>>2]=0x6c6c6c6c; view32[4836>>2]=0x56565656; view32[4840>>2]=0xf4f4f4f4; view32[4844>>2]=0xeaeaeaea;
view32[4848>>2]=0x65656565; view32[4852>>2]=0x7a7a7a7a; view32[4856>>2]=0xaeaeaeae; view32[4860>>2]=0x08080808;
view32[4864>>2]=0xbabababa; view32[4868>>2]=0x78787878; view32[4872>>2]=0x25252525; view32[4876>>2]=0x2e2e2e2e;
view32[4880>>2]=0x1c1c1c1c; view32[4884>>2]=0xa6a6a6a6; view32[4888>>2]=0xb4b4b4b4; view32[4892>>2]=0xc6c6c6c6;
view32[4896>>2]=0xe8e8e8e8; view32[4900>>2]=0xdddddddd; view32[4904>>2]=0x74747474; view32[4908>>2]=0x1f1f1f1f;
view32[4912>>2]=0x4b4b4b4b; view32[4916>>2]=0xbdbdbdbd; view32[4920>>2]=0x8b8b8b8b; view32[4924>>2]=0x8a8a8a8a;
view32[4928>>2]=0x70707070; view32[4932>>2]=0x3e3e3e3e; view32[4936>>2]=0xb5b5b5b5; view32[4940>>2]=0x66666666;
view32[4944>>2]=0x48484848; view32[4948>>2]=0x03030303; view32[4952>>2]=0xf6f6f6f6; view32[4956>>2]=0x0e0e0e0e;
view32[4960>>2]=0x61616161; view32[4964>>2]=0x35353535; view32[4968>>2]=0x57575757; view32[4972>>2]=0xb9b9b9b9;
view32[4976>>2]=0x86868686; view32[4980>>2]=0xc1c1c1c1; view32[4984>>2]=0x1d1d1d1d; view32[4988>>2]=0x9e9e9e9e;
view32[4992>>2]=0xe1e1e1e1; view32[4996>>2]=0xf8f8f8f8; view32[5000>>2]=0x98989898; view32[5004>>2]=0x11111111;
view32[5008>>2]=0x69696969; view32[5012>>2]=0xd9d9d9d9; view32[5016>>2]=0x8e8e8e8e; view32[5020>>2]=0x94949494;
view32[5024>>2]=0x9b9b9b9b; view32[5028>>2]=0x1e1e1e1e; view32[5032>>2]=0x87878787; view32[5036>>2]=0xe9e9e9e9;
view32[5040>>2]=0xcececece; view32[5044>>2]=0x55555555; view32[5048>>2]=0x28282828; view32[5052>>2]=0xdfdfdfdf;
view32[5056>>2]=0x8c8c8c8c; view32[5060>>2]=0xa1a1a1a1; view32[5064>>2]=0x89898989; view32[5068>>2]=0x0d0d0d0d;
view32[5072>>2]=0xbfbfbfbf; view32[5076>>2]=0xe6e6e6e6; view32[5080>>2]=0x42424242; view32[5084>>2]=0x68686868;
view32[5088>>2]=0x41414141; view32[5092>>2]=0x99999999; view32[5096>>2]=0x2d2d2d2d; view32[5100>>2]=0x0f0f0f0f;
view32[5104>>2]=0xb0b0b0b0; view32[5108>>2]=0x54545454; view32[5112>>2]=0xbbbbbbbb; view32[5116>>2]=0x16161616;

// Load the rcon lookup table
view8[10240]=0x01; view8[10241]=0x02; view8[10242]=0x04; view8[10243]=0x08;
view8[10244]=0x10; view8[10245]=0x20; view8[10246]=0x40; view8[10247]=0x80;
view8[10248]=0x1B; view8[10249]=0x36;
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
			var p = 0, genLen = 0, i = 0;
			var temp = 0;
			bitLength = 256;

			// Copy the first 8 words
			for(p = 0, genLen = 0 ; (p|0) < 32 ; p = (p + 4)|0, genLen = (genLen + 4)|0) {
				view32[(rk + p) >> 2] = view32[(key + p) >> 2];
			}

			while((genLen|0) < 240) {
				// Save previous word
				temp = view32[(rk + genLen - 4) >> 2]|0;

				// Apply Schedule Core (rotate, s-box lookup, xor rcon)
				temp = (
					( view32[(Te4 + (((temp >>>  0) & 0xff) << 2)) >> 2] & 0xff000000) ^
					( view32[(Te4 + (((temp >>> 24)       ) << 2)) >> 2] & 0x00ff0000) ^
					( view32[(Te4 + (((temp >>> 16) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
					((view32[(Te4 + (((temp >>>  8) & 0xff) << 2)) >> 2] & 0x000000ff) ^
						view8[(rcon + i)|0])
				);
				i = (i + 1)|0;

				// Store new word
				view32[(rk + genLen) >> 2] = temp ^ view32[(rk + genLen - 32) >> 2];
				genLen = (genLen + 4)|0;

				// Store next 3 words
				for(p = 0 ; (p|0) < 12 ; p = (p + 4)|0, genLen = (genLen + 4)|0) {
					view32[(rk + genLen) >> 2] = view32[(rk + genLen - 32) >> 2] ^ view32[(rk + genLen - 4) >> 2];
				}

				if((bitLength|0) == 256) {
					// Save previous word
					temp = view32[(rk + genLen - 4) >> 2]|0;

					// Apply S-box
					temp = (
						(view32[(Te4 + (((temp >>> 24)       ) << 2)) >> 2] & 0xff000000) ^
						(view32[(Te4 + (((temp >>> 16) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
						(view32[(Te4 + (((temp >>>  8) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
						(view32[(Te4 + (((temp       ) & 0xff) << 2)) >> 2] & 0x000000ff)
					);

					// Store new word
					view32[(rk + genLen) >> 2] = temp ^ view32[(rk + genLen - 32) >> 2];
					genLen = (genLen + 4)|0;

					// Store next 3 words
					for(p = 0 ; (p|0) < 12 ; p = (p + 4)|0, genLen = (genLen + 4)|0) {
						view32[(rk + genLen) >> 2] = view32[(rk + genLen - 32) >> 2] ^ view32[(rk + genLen - 4) >> 2];
					}
				}
			}

			return 14;
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
					(view32[(Te0 + (((s0 >> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((s1 >> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((s2 >>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((s3      ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk + 16) >> 2]);

				t1 =
					(view32[(Te0 + (((s1 >> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((s2 >> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((s3 >>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((s0      ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk + 20) >> 2]);

				t2 =
					(view32[(Te0 + (((s2 >> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((s3 >> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((s0 >>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((s1      ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk + 24) >> 2]);

				t3 =
					(view32[(Te0 + (((s3 >> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((s0 >> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((s1 >>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((s2      ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk + 28) >> 2]);

				rk = (rk + 32)|0;
				r = (r - 1)|0;
				if((r|0) == 0) {
					break;
				}

				s0 =
					(view32[(Te0 + (((t0 >> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((t1 >> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((t2 >>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((t3      ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk     ) >> 2]);

				s1 =
					(view32[(Te0 + (((t1 >> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((t2 >> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((t3 >>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((t0      ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk +  4) >> 2]);

				s2 =
					(view32[(Te0 + (((t2 >> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((t3 >> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((t0 >>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((t1      ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk +  8) >> 2]);

				s3 =
					(view32[(Te0 + (((t3 >> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((t0 >> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((t1 >>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((t2      ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk + 12) >> 2]);
			}

			// Apply the last round and copy the cipher state into the ciphertext.
			s0 =
				(view32[(Te4 + (((t0 >> 24)       ) << 2)) >> 2] & 0xff000000) ^
				(view32[(Te4 + (((t1 >> 16) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
				(view32[(Te4 + (((t2 >>  8) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
				(view32[(Te4 + (((t3      ) & 0xff) << 2)) >> 2] & 0x000000ff) ^
				(view32[(rk     ) >> 2]);
			wtob((cipher     )|0, s0);

			s1 =
				(view32[(Te4 + (((t1 >> 24)       ) << 2)) >> 2] & 0xff000000) ^
				(view32[(Te4 + (((t2 >> 16) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
				(view32[(Te4 + (((t3 >>  8) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
				(view32[(Te4 + (((t0      ) & 0xff) << 2)) >> 2] & 0x000000ff) ^
				(view32[(rk +  4) >> 2]);
			wtob((cipher +  4)|0, s1);

			s2 =
				(view32[(Te4 + (((t2 >> 24)       ) << 2)) >> 2] & 0xff000000) ^
				(view32[(Te4 + (((t3 >> 16) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
				(view32[(Te4 + (((t0 >>  8) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
				(view32[(Te4 + (((t1      ) & 0xff) << 2)) >> 2] & 0x000000ff) ^
				(view32[(rk +  8) >> 2]);
			wtob((cipher +  8)|0, s2);

			s3 =
				(view32[(Te4 + (((t3 >> 24)       ) << 2)) >> 2] & 0xff000000) ^
				(view32[(Te4 + (((t0 >> 16) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
				(view32[(Te4 + (((t1 >>  8) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
				(view32[(Te4 + (((t2      ) & 0xff) << 2)) >> 2] & 0x000000ff) ^
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

	var heap = new ArrayBuffer(heapSize);
	var heap8 = new Uint8Array(heap);
	var asm = aesAsm(window, undefined, heap);
	asm.init();

	/**
	 * @param {String} password
	 * @param {String} data
	 * @returns {ArrayBuffer}
	 */
	function encrypt(password, data) {
		var ciphertext, ciphertextLen, ciphertextOffset, nRounds, dataOffset, copyLen, padLen;
		var i, j;

		// TODO Create a real key from the password.
		for(i = 0 ; i < 32 ; i++) {
			heap8[keyOffset + i] = 0;//65 + i;
		}
		nRounds = asm.createEncrypt(rkOffset, keyOffset);

		while(data.length % 8 != 0) {
			data += 0;
		}

		ciphertext = new ArrayBuffer(data.length * 2);
		for(i = 0, j = 0 ; i < data.length ; i += 8, j += 16) {
			CS.nStringInToArrayBuffer(heap, plainOffset, data, i, 8);
			asm.encrypt(rkOffset, nRounds, plainOffset, cipherOffset);
			CS.arrayBufferInToArrayBuffer(ciphertext, j, heap, cipherOffset, 16);
		}

		/*ciphertextLen = data.length * 2;
		ciphertext = new ArrayBuffer(ciphertextLen);
		for(
				dataOffset = 0, ciphertextOffset = 0 ;
				ciphertextLen > 0 ;
				dataOffset += copyLen, ciphertextOffset += copyLen, ciphertextLen -= copyLen
			) {
			copyLen = Math.min(ciphertextLen, 8);
			padLen = 7 - copyLen;
			CS.nStringInToArrayBuffer(heap, plainOffset, data, dataOffset, copyLen);
			// Add padding to finish the 16-byte block
			while(padLen >= 0) {
				heap8[plainOffset + copyLen + padLen] = 0;
				padLen -= 1;
			}
			asm.encrypt(rkOffset, nRounds, plainOffset, cipherOffset);
			CS.arrayBufferInToArrayBuffer(ciphertext, ciphertextOffset, heap, cipherOffset, 16);
		}*/
		// TODO copy the ciphertext buffer to an ArrayBuffer.
		return ciphertext;
	}

	function decrypt(password, data) {
		// TODO Create a real key from the password.
		for(var i = 0 ; i < 32 ; i++) {
			heap8[keyOffset + i] = 0;//65 + i;
		}
		var nRounds = asm.createDecrypt(rkOffset, keyOffset);
		// TODO process data 16 bytes (8 characters) at a time.
		// TODO copy data into the ciphertext buffer.
		asm.decrypt(rkOffset, nRounds, cipherOffset, plainOffset);
		// TODO copy the plaintext buffer to a string.
		return "";
	}

	/*function testEncrypt() {
		var i, nRounds, hex;
		// set the key
		for(i = 0 ; i < 32 ; i++) {
			heap8[keyOffset + i] = 0;
		}
		console.log("key        = " + Hex.toHex(heap, keyOffset, 32));
		nRounds = asm.createEncrypt(rkOffset, keyOffset);
		heap8[plainOffset] = 0x80;
		for(i = 1 ; i < 16 ; i++) {
			heap8[plainOffset + i] = 0;
		}
		console.log("plaintext  = " + Hex.toHex(heap, plainOffset, 16));
		asm.encrypt(rkOffset, nRounds, plainOffset, cipherOffset);
		hex = Hex.toHex(heap, cipherOffset, 16);
		console.log("ciphertext = " + hex);
	}*/
	function testEncrypt() {
		var i, j, nRounds, hex;
		var keyView = new Uint8Array(heap, keyOffset, 32);

		// set the key
		for(i = 0 ; i < 32 ; i++) {
			keyView[i] = i;
		}

		nRounds = asm.createEncrypt(rkOffset, keyOffset);
		for(var k = 0 ; k < 240 ; k += 16) {
			console.log(Hex.toHex(heap, rkOffset + k, 16));
		}
	}

	return {
		"encrypt": encrypt,
		"decrypt": decrypt,
		"testEncrypt": testEncrypt
	}

}();
