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

		var logHex = foreign.logHex;
		var view8  = new stdlib.Uint8Array(heap);
		var view32 = new stdlib.Uint32Array(heap);
		var viewInt = new stdlib.Int32Array(heap);
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
		var pow = 10280; // +1024b
		var log = 11304; // +1024b

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

		function xTime(x) {
			x = x|0;
			return ((x << 1) ^ ((x & 0x80) == 0 ? 0x00 : 0x1B))|0;
		}

		function rotate(x) {
			x = x|0;
			return ((x << 8) & 0xFFFFFFFF) | (x >>> 24) ;
//			return (x >>> 8) | (x << 24);
		}

		function multiply(x, y) {
			x = x|0;
			y = y|0;
			var p = 0, lx = 0, ly = 0;
			if(x != 0 && y != 0) {
				lx = viewInt[(log + (x << 2)) >> 2];
				ly = viewInt[(log + (y << 2)) >> 2];
				p = viewInt[(pow + (((lx + ly) % 255) << 2)) >> 2];
			}
			return p|0;
		}

		/*
		// apply rotation
		//temp = (temp >>> 8) | (temp << 24);
		 */

		function sboxes() {
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

// Load the Td4 lookup table
view32[9216>>2]=0x52525252; view32[9220>>2]=0x09090909; view32[9224>>2]=0x6a6a6a6a; view32[9228>>2]=0xd5d5d5d5;
view32[9232>>2]=0x30303030; view32[9236>>2]=0x36363636; view32[9240>>2]=0xa5a5a5a5; view32[9244>>2]=0x38383838;
view32[9248>>2]=0xbfbfbfbf; view32[9252>>2]=0x40404040; view32[9256>>2]=0xa3a3a3a3; view32[9260>>2]=0x9e9e9e9e;
view32[9264>>2]=0x81818181; view32[9268>>2]=0xf3f3f3f3; view32[9272>>2]=0xd7d7d7d7; view32[9276>>2]=0xfbfbfbfb;
view32[9280>>2]=0x7c7c7c7c; view32[9284>>2]=0xe3e3e3e3; view32[9288>>2]=0x39393939; view32[9292>>2]=0x82828282;
view32[9296>>2]=0x9b9b9b9b; view32[9300>>2]=0x2f2f2f2f; view32[9304>>2]=0xffffffff; view32[9308>>2]=0x87878787;
view32[9312>>2]=0x34343434; view32[9316>>2]=0x8e8e8e8e; view32[9320>>2]=0x43434343; view32[9324>>2]=0x44444444;
view32[9328>>2]=0xc4c4c4c4; view32[9332>>2]=0xdededede; view32[9336>>2]=0xe9e9e9e9; view32[9340>>2]=0xcbcbcbcb;
view32[9344>>2]=0x54545454; view32[9348>>2]=0x7b7b7b7b; view32[9352>>2]=0x94949494; view32[9356>>2]=0x32323232;
view32[9360>>2]=0xa6a6a6a6; view32[9364>>2]=0xc2c2c2c2; view32[9368>>2]=0x23232323; view32[9372>>2]=0x3d3d3d3d;
view32[9376>>2]=0xeeeeeeee; view32[9380>>2]=0x4c4c4c4c; view32[9384>>2]=0x95959595; view32[9388>>2]=0x0b0b0b0b;
view32[9392>>2]=0x42424242; view32[9396>>2]=0xfafafafa; view32[9400>>2]=0xc3c3c3c3; view32[9404>>2]=0x4e4e4e4e;
view32[9408>>2]=0x08080808; view32[9412>>2]=0x2e2e2e2e; view32[9416>>2]=0xa1a1a1a1; view32[9420>>2]=0x66666666;
view32[9424>>2]=0x28282828; view32[9428>>2]=0xd9d9d9d9; view32[9432>>2]=0x24242424; view32[9436>>2]=0xb2b2b2b2;
view32[9440>>2]=0x76767676; view32[9444>>2]=0x5b5b5b5b; view32[9448>>2]=0xa2a2a2a2; view32[9452>>2]=0x49494949;
view32[9456>>2]=0x6d6d6d6d; view32[9460>>2]=0x8b8b8b8b; view32[9464>>2]=0xd1d1d1d1; view32[9468>>2]=0x25252525;
view32[9472>>2]=0x72727272; view32[9476>>2]=0xf8f8f8f8; view32[9480>>2]=0xf6f6f6f6; view32[9484>>2]=0x64646464;
view32[9488>>2]=0x86868686; view32[9492>>2]=0x68686868; view32[9496>>2]=0x98989898; view32[9500>>2]=0x16161616;
view32[9504>>2]=0xd4d4d4d4; view32[9508>>2]=0xa4a4a4a4; view32[9512>>2]=0x5c5c5c5c; view32[9516>>2]=0xcccccccc;
view32[9520>>2]=0x5d5d5d5d; view32[9524>>2]=0x65656565; view32[9528>>2]=0xb6b6b6b6; view32[9532>>2]=0x92929292;
view32[9536>>2]=0x6c6c6c6c; view32[9540>>2]=0x70707070; view32[9544>>2]=0x48484848; view32[9548>>2]=0x50505050;
view32[9552>>2]=0xfdfdfdfd; view32[9556>>2]=0xedededed; view32[9560>>2]=0xb9b9b9b9; view32[9564>>2]=0xdadadada;
view32[9568>>2]=0x5e5e5e5e; view32[9572>>2]=0x15151515; view32[9576>>2]=0x46464646; view32[9580>>2]=0x57575757;
view32[9584>>2]=0xa7a7a7a7; view32[9588>>2]=0x8d8d8d8d; view32[9592>>2]=0x9d9d9d9d; view32[9596>>2]=0x84848484;
view32[9600>>2]=0x90909090; view32[9604>>2]=0xd8d8d8d8; view32[9608>>2]=0xabababab; view32[9612>>2]=0x00000000;
view32[9616>>2]=0x8c8c8c8c; view32[9620>>2]=0xbcbcbcbc; view32[9624>>2]=0xd3d3d3d3; view32[9628>>2]=0x0a0a0a0a;
view32[9632>>2]=0xf7f7f7f7; view32[9636>>2]=0xe4e4e4e4; view32[9640>>2]=0x58585858; view32[9644>>2]=0x05050505;
view32[9648>>2]=0xb8b8b8b8; view32[9652>>2]=0xb3b3b3b3; view32[9656>>2]=0x45454545; view32[9660>>2]=0x06060606;
view32[9664>>2]=0xd0d0d0d0; view32[9668>>2]=0x2c2c2c2c; view32[9672>>2]=0x1e1e1e1e; view32[9676>>2]=0x8f8f8f8f;
view32[9680>>2]=0xcacacaca; view32[9684>>2]=0x3f3f3f3f; view32[9688>>2]=0x0f0f0f0f; view32[9692>>2]=0x02020202;
view32[9696>>2]=0xc1c1c1c1; view32[9700>>2]=0xafafafaf; view32[9704>>2]=0xbdbdbdbd; view32[9708>>2]=0x03030303;
view32[9712>>2]=0x01010101; view32[9716>>2]=0x13131313; view32[9720>>2]=0x8a8a8a8a; view32[9724>>2]=0x6b6b6b6b;
view32[9728>>2]=0x3a3a3a3a; view32[9732>>2]=0x91919191; view32[9736>>2]=0x11111111; view32[9740>>2]=0x41414141;
view32[9744>>2]=0x4f4f4f4f; view32[9748>>2]=0x67676767; view32[9752>>2]=0xdcdcdcdc; view32[9756>>2]=0xeaeaeaea;
view32[9760>>2]=0x97979797; view32[9764>>2]=0xf2f2f2f2; view32[9768>>2]=0xcfcfcfcf; view32[9772>>2]=0xcececece;
view32[9776>>2]=0xf0f0f0f0; view32[9780>>2]=0xb4b4b4b4; view32[9784>>2]=0xe6e6e6e6; view32[9788>>2]=0x73737373;
view32[9792>>2]=0x96969696; view32[9796>>2]=0xacacacac; view32[9800>>2]=0x74747474; view32[9804>>2]=0x22222222;
view32[9808>>2]=0xe7e7e7e7; view32[9812>>2]=0xadadadad; view32[9816>>2]=0x35353535; view32[9820>>2]=0x85858585;
view32[9824>>2]=0xe2e2e2e2; view32[9828>>2]=0xf9f9f9f9; view32[9832>>2]=0x37373737; view32[9836>>2]=0xe8e8e8e8;
view32[9840>>2]=0x1c1c1c1c; view32[9844>>2]=0x75757575; view32[9848>>2]=0xdfdfdfdf; view32[9852>>2]=0x6e6e6e6e;
view32[9856>>2]=0x47474747; view32[9860>>2]=0xf1f1f1f1; view32[9864>>2]=0x1a1a1a1a; view32[9868>>2]=0x71717171;
view32[9872>>2]=0x1d1d1d1d; view32[9876>>2]=0x29292929; view32[9880>>2]=0xc5c5c5c5; view32[9884>>2]=0x89898989;
view32[9888>>2]=0x6f6f6f6f; view32[9892>>2]=0xb7b7b7b7; view32[9896>>2]=0x62626262; view32[9900>>2]=0x0e0e0e0e;
view32[9904>>2]=0xaaaaaaaa; view32[9908>>2]=0x18181818; view32[9912>>2]=0xbebebebe; view32[9916>>2]=0x1b1b1b1b;
view32[9920>>2]=0xfcfcfcfc; view32[9924>>2]=0x56565656; view32[9928>>2]=0x3e3e3e3e; view32[9932>>2]=0x4b4b4b4b;
view32[9936>>2]=0xc6c6c6c6; view32[9940>>2]=0xd2d2d2d2; view32[9944>>2]=0x79797979; view32[9948>>2]=0x20202020;
view32[9952>>2]=0x9a9a9a9a; view32[9956>>2]=0xdbdbdbdb; view32[9960>>2]=0xc0c0c0c0; view32[9964>>2]=0xfefefefe;
view32[9968>>2]=0x78787878; view32[9972>>2]=0xcdcdcdcd; view32[9976>>2]=0x5a5a5a5a; view32[9980>>2]=0xf4f4f4f4;
view32[9984>>2]=0x1f1f1f1f; view32[9988>>2]=0xdddddddd; view32[9992>>2]=0xa8a8a8a8; view32[9996>>2]=0x33333333;
view32[10000>>2]=0x88888888; view32[10004>>2]=0x07070707; view32[10008>>2]=0xc7c7c7c7; view32[10012>>2]=0x31313131;
view32[10016>>2]=0xb1b1b1b1; view32[10020>>2]=0x12121212; view32[10024>>2]=0x10101010; view32[10028>>2]=0x59595959;
view32[10032>>2]=0x27272727; view32[10036>>2]=0x80808080; view32[10040>>2]=0xecececec; view32[10044>>2]=0x5f5f5f5f;
view32[10048>>2]=0x60606060; view32[10052>>2]=0x51515151; view32[10056>>2]=0x7f7f7f7f; view32[10060>>2]=0xa9a9a9a9;
view32[10064>>2]=0x19191919; view32[10068>>2]=0xb5b5b5b5; view32[10072>>2]=0x4a4a4a4a; view32[10076>>2]=0x0d0d0d0d;
view32[10080>>2]=0x2d2d2d2d; view32[10084>>2]=0xe5e5e5e5; view32[10088>>2]=0x7a7a7a7a; view32[10092>>2]=0x9f9f9f9f;
view32[10096>>2]=0x93939393; view32[10100>>2]=0xc9c9c9c9; view32[10104>>2]=0x9c9c9c9c; view32[10108>>2]=0xefefefef;
view32[10112>>2]=0xa0a0a0a0; view32[10116>>2]=0xe0e0e0e0; view32[10120>>2]=0x3b3b3b3b; view32[10124>>2]=0x4d4d4d4d;
view32[10128>>2]=0xaeaeaeae; view32[10132>>2]=0x2a2a2a2a; view32[10136>>2]=0xf5f5f5f5; view32[10140>>2]=0xb0b0b0b0;
view32[10144>>2]=0xc8c8c8c8; view32[10148>>2]=0xebebebeb; view32[10152>>2]=0xbbbbbbbb; view32[10156>>2]=0x3c3c3c3c;
view32[10160>>2]=0x83838383; view32[10164>>2]=0x53535353; view32[10168>>2]=0x99999999; view32[10172>>2]=0x61616161;
view32[10176>>2]=0x17171717; view32[10180>>2]=0x2b2b2b2b; view32[10184>>2]=0x04040404; view32[10188>>2]=0x7e7e7e7e;
view32[10192>>2]=0xbabababa; view32[10196>>2]=0x77777777; view32[10200>>2]=0xd6d6d6d6; view32[10204>>2]=0x26262626;
view32[10208>>2]=0xe1e1e1e1; view32[10212>>2]=0x69696969; view32[10216>>2]=0x14141414; view32[10220>>2]=0x63636363;
view32[10224>>2]=0x55555555; view32[10228>>2]=0x21212121; view32[10232>>2]=0x0c0c0c0c; view32[10236>>2]=0x7d7d7d7d;
		}

		function init() {
			// temporarily stored these thousands of statements in init.js so my IDE
			// isn't slow to analyse the code under active development.
			sboxes();
			var powView = new Int32Array(heap, pow, 256);
			var te0View = new Uint8Array(heap, Te0, 1024);

			var i = 0, x = 0, y = 0, z = 0;

			// Calculate pow and log tables
			for(i = 0, x = 1 ; (i|0) < 256 ; i = (i + 1)|0) {
				viewInt[(pow + (i << 2)) >> 2] = x|0;
				viewInt[(log + (x << 2)) >> 2] = i|0;
				x = (x ^ xTime(x)) & 0xFF;
			}

			// Calculate lookup tables
			for(i = 0 ; (i|0) < 256 ; i = (i + 1)|0) {
				x = view32[(Te4 + (i << 2)) >> 2] & 0xFF;
				y = xTime(x) & 0xFF;
				z = (y ^ x) & 0xFF;

				view32[(Te0 + (i << 2)) >> 2] =
					(y) ^
						(x << 8) ^
						(x << 16) ^
						(z << 24);

				view32[(Te1 + (i << 2)) >> 2] = rotate(view32[(Te0 + (i << 2)) >> 2]);
				view32[(Te2 + (i << 2)) >> 2] = rotate(view32[(Te1 + (i << 2)) >> 2]);
				view32[(Te3 + (i << 2)) >> 2] = rotate(view32[(Te2 + (i << 2)) >> 2]);

//				x = view32[(Td4 + (i << 2)) >> 2];
			}

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
			var i = 0;
			var temp = 0;
			bitLength = 256;

			// Copy the first 4 words
			view32[(rk     ) >> 2] = view32[(key     ) >> 2]; // [0]
			view32[(rk +  4) >> 2] = view32[(key +  4) >> 2]; // [1]
			view32[(rk +  8) >> 2] = view32[(key +  8) >> 2]; // [2]
			view32[(rk + 12) >> 2] = view32[(key + 12) >> 2]; // [3]

			// 128-bit key

			// Copy the next 2 words
			view32[(rk + 16) >> 2] = view32[(key + 16) >> 2]; // [4]
			view32[(rk + 20) >> 2] = view32[(key + 20) >> 2]; // [5]

			// 192-bit key

			// Copy the next 2 words
			view32[(rk + 24) >> 2] = view32[(key + 24) >> 2]; // [6]
			view32[(rk + 28) >> 2] = view32[(key + 28) >> 2]; // [7]

			// 256-bit key
			if((bitLength|0) == 256) {
				for( ; ; ) {
					// Save previous word
					temp = view32[(rk + 28) >> 2]|0; // [7]

					// Apply the Schedule Core (rotate, s-box lookup, xor rcon)
					// Xor it with the 8th word back
					// Store the new word
					view32[(rk + 32) >> 2] = ( // [8]
						(view32[(rk) >> 2]) ^  // [0]
						(
							(view32[(Te4 + (((temp >>>  0) & 0xff) << 2)) >> 2] & 0xff000000) ^
							(view32[(Te4 + (((temp >>> 24)       ) << 2)) >> 2] & 0x00ff0000) ^
							(view32[(Te4 + (((temp >>> 16) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
							(
								(view32[(Te4 + (((temp >>>  8) & 0xff) << 2)) >> 2] & 0x000000ff) ^
								(view8[(rcon + i)|0])
							)
						)
					);

					// Store the next 3 words
					view32[(rk + 36) >> 2] = view32[(rk +  4) >> 2] ^ view32[(rk + 32) >> 2]; // [ 9] = [ 1] ^ [ 8]
					view32[(rk + 40) >> 2] = view32[(rk +  8) >> 2] ^ view32[(rk + 36) >> 2]; // [10] = [ 2] ^ [ 9]
					view32[(rk + 44) >> 2] = view32[(rk + 12) >> 2] ^ view32[(rk + 40) >> 2]; // [11] = [ 3] ^ [10]

					// Check if the schedule is full
					i = (i + 1)|0;
					if((i|0) == 7) {
						return 14;
					}

					// Save previous word
					temp = view32[(rk + 44) >> 2]|0; // [11]

					// Apply S-box lookup
					// Xor it with the 8th word back
					// Store the new word
					view32[(rk + 48) >> 2] = ( // [12]
						(view32[(rk + 16) >> 2]) ^ // [ 4]
						(
							(view32[(Te4 + (((temp >>> 24)       ) << 2)) >> 2] & 0xff000000) ^
							(view32[(Te4 + (((temp >>> 16) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
							(view32[(Te4 + (((temp >>>  8) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
							(view32[(Te4 + (((temp       ) & 0xff) << 2)) >> 2] & 0x000000ff)
						)
					);

					// Store the next 3 words
					view32[(rk + 52) >> 2] = view32[(rk + 20) >> 2] ^ view32[(rk + 48) >> 2]; // [13] = [ 5] ^ [12]
					view32[(rk + 56) >> 2] = view32[(rk + 24) >> 2] ^ view32[(rk + 52) >> 2]; // [14] = [ 6] ^ [13]
					view32[(rk + 60) >> 2] = view32[(rk + 28) >> 2] ^ view32[(rk + 56) >> 2]; // [15] = [ 7] ^ [14]

					// Move pointer to the next 32-bit block
					rk = (rk + 32)|0;
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
			s0 = view32[(plain     ) >> 2] ^ view32[(rk     ) >> 2];
			s1 = view32[(plain +  4) >> 2] ^ view32[(rk +  4) >> 2];
			s2 = view32[(plain +  8) >> 2] ^ view32[(rk +  8) >> 2];
			s3 = view32[(plain + 12) >> 2] ^ view32[(rk + 12) >> 2];

			// TODO Unroll the loop
			// Use a loop to apply the rounds
			r = nRounds >>> 1;
			for( ; ; ) {
				t0 =
					/*
					(view32[(Te4 + (((temp >>> 24)       ) << 2)) >> 2] & 0xff000000) ^
					(view32[(Te4 + (((temp >>> 16) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
					(view32[(Te4 + (((temp >>>  8) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
					(view32[(Te4 + (((temp       ) & 0xff) << 2)) >> 2] & 0x000000ff) */
					(view32[(Te0 +   (((s0 >>> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 +   (((s1 >>> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 +   (((s2 >>>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 +   (((s3       ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk + 16) >> 2]); // [4]
				view32[(cipher     ) >> 2] = t0;

				t1 =
					(view32[(Te0 + (((s1 >>> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((s2 >>> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((s3 >>>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((s0       ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk + 20) >> 2]); // [5]
				view32[(cipher +  4) >> 2] = t1;

				t2 =
					(view32[(Te0 + (((s2 >>> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((s3 >>> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((s0 >>>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((s1       ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk + 24) >> 2]); // [6]
				view32[(cipher +  8) >> 2] = t2;

				t3 =
					(view32[(Te0 + (((s3 >>> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((s0 >>> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((s1 >>>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((s2       ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk + 28) >> 2]); // [7]
				view32[(cipher + 12) >> 2] = t3;

				logHex((cipher|0), 16);

				// Check if all needed rounds have been done
				rk = (rk + 32)|0;
				r = (r - 1)|0;
				if((r|0) == 0) {
					break;
				}

				s0 =
					(view32[(Te0 + (((t0 >>> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((t1 >>> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((t2 >>>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((t3       ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk     ) >> 2]); // [0]
				view32[(cipher     ) >> 2] = s0;

				s1 =
					(view32[(Te0 + (((t1 >>> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((t2 >>> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((t3 >>>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((t0       ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk +  4) >> 2]); // [1]
				view32[(cipher +  4) >> 2] = s1;

				s2 =
					(view32[(Te0 + (((t2 >>> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((t3 >>> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((t0 >>>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((t1       ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk +  8) >> 2]); // [2]
				view32[(cipher +  8) >> 2] = s2;

				s3 =
					(view32[(Te0 + (((t3 >>> 24)       ) << 2)) >> 2]) ^
					(view32[(Te1 + (((t0 >>> 16) & 0xff) << 2)) >> 2]) ^
					(view32[(Te2 + (((t1 >>>  8) & 0xff) << 2)) >> 2]) ^
					(view32[(Te3 + (((t2       ) & 0xff) << 2)) >> 2]) ^
					(view32[(rk + 12) >> 2]); // [3]
				view32[(cipher + 12) >> 2] = s3;

				logHex((cipher|0), 16);
			}

			// Apply the last round and copy the cipher state into the ciphertext.
			s0 =
				/*
				(view32[(Te4 + (((temp >>> 24)       ) << 2)) >> 2] & 0xff000000) ^
				(view32[(Te4 + (((temp >>> 16) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
				(view32[(Te4 + (((temp >>>  8) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
				(view32[(Te4 + (((temp       ) & 0xff) << 2)) >> 2] & 0x000000ff)*/
				(view32[(Te4 +   (((t0 >>> 24)       ) << 2)) >> 2] & 0xff000000) ^
				(view32[(Te4 +   (((t1 >>> 16) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
				(view32[(Te4 +   (((t2 >>>  8) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
				(view32[(Te4 +   (((t3       ) & 0xff) << 2)) >> 2] & 0x000000ff) ^
				(view32[(rk     ) >> 2]);
			 /* (view32[(rk + 16) >> 2]) ^ // [ 4] */
			view32[(cipher     ) >> 2] = s0;

			s1 =
				(view32[(Te4 + (((t1 >>> 24)       ) << 2)) >> 2] & 0xff000000) ^
				(view32[(Te4 + (((t2 >>> 16) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
				(view32[(Te4 + (((t3 >>>  8) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
				(view32[(Te4 + (((t0       ) & 0xff) << 2)) >> 2] & 0x000000ff) ^
				(view32[(rk +  4) >> 2]);
			view32[(cipher +  4) >> 2] = s1;

			s2 =
				(view32[(Te4 + (((t2 >>> 24)       ) << 2)) >> 2] & 0xff000000) ^
				(view32[(Te4 + (((t3 >>> 16) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
				(view32[(Te4 + (((t0 >>>  8) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
				(view32[(Te4 + (((t1       ) & 0xff) << 2)) >> 2] & 0x000000ff) ^
				(view32[(rk +  8) >> 2]);
			view32[(cipher +  8) >> 2] = s2;

			s3 =
				(view32[(Te4 + (((t3 >>> 24)       ) << 2)) >> 2] & 0xff000000) ^
				(view32[(Te4 + (((t0 >>> 16) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
				(view32[(Te4 + (((t1 >>>  8) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
				(view32[(Te4 + (((t2       ) & 0xff) << 2)) >> 2] & 0x000000ff) ^
				(view32[(rk + 12) >> 2]);
			view32[(cipher + 12) >> 2] = s3;
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
	var asm = aesAsm(window, {"logHex": logHex}, heap);
	//asm.init();

	function logHex(pointer, len) {
		console.log(Hex.toHex(heap, pointer, len));
	}

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
		asm.init();
		var i, j, nRounds, hex;
		var keyView = new Uint8Array(heap, keyOffset, 32);
		var plainView = new Uint8Array(heap, plainOffset, 16);

		// set the key
		for(i = 0 ; i < 32 ; i++) {
			keyView[i] = i;
		}

		// init encryption
		nRounds = asm.createEncrypt(rkOffset, keyOffset);
		// log key schedule
		/*for(var k = 0 ; k < 240 ; k += 16) {
			console.log("RK" + ((k/16)|0) + "=" + Hex.toHex(heap, rkOffset + k, 16));
		}*/

		// set the plaintext
		for(i = 0 ; i < 16 ; i++) {
			plainView[i] = i * 16 + i;
		}
		console.log("PT=" + Hex.toHex(heap, plainOffset, 16));

		// encrypt
		asm.encrypt(rkOffset, nRounds, plainOffset, cipherOffset);
		// log the ciphertext
		console.log("CT=" + Hex.toHex(heap, cipherOffset, 16));
	}

	return {
		"encrypt": encrypt,
		"decrypt": decrypt,
		"testEncrypt": testEncrypt
	}

}();
