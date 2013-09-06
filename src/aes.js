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
// Load the Te0 lookup table
			view32[0>>2]=0xc66363a5; view32[4>>2]=0xf87c7c84; view32[8>>2]=0xee777799; view32[12>>2]=0xf67b7b8d;
			view32[16>>2]=0xfff2f20d; view32[20>>2]=0xd66b6bbd; view32[24>>2]=0xde6f6fb1; view32[28>>2]=0x91c5c554;
			view32[32>>2]=0x60303050; view32[36>>2]=0x02010103; view32[40>>2]=0xce6767a9; view32[44>>2]=0x562b2b7d;
			view32[48>>2]=0xe7fefe19; view32[52>>2]=0xb5d7d762; view32[56>>2]=0x4dababe6; view32[60>>2]=0xec76769a;
			view32[64>>2]=0x8fcaca45; view32[68>>2]=0x1f82829d; view32[72>>2]=0x89c9c940; view32[76>>2]=0xfa7d7d87;
			view32[80>>2]=0xeffafa15; view32[84>>2]=0xb25959eb; view32[88>>2]=0x8e4747c9; view32[92>>2]=0xfbf0f00b;
			view32[96>>2]=0x41adadec; view32[100>>2]=0xb3d4d467; view32[104>>2]=0x5fa2a2fd; view32[108>>2]=0x45afafea;
			view32[112>>2]=0x239c9cbf; view32[116>>2]=0x53a4a4f7; view32[120>>2]=0xe4727296; view32[124>>2]=0x9bc0c05b;
			view32[128>>2]=0x75b7b7c2; view32[132>>2]=0xe1fdfd1c; view32[136>>2]=0x3d9393ae; view32[140>>2]=0x4c26266a;
			view32[144>>2]=0x6c36365a; view32[148>>2]=0x7e3f3f41; view32[152>>2]=0xf5f7f702; view32[156>>2]=0x83cccc4f;
			view32[160>>2]=0x6834345c; view32[164>>2]=0x51a5a5f4; view32[168>>2]=0xd1e5e534; view32[172>>2]=0xf9f1f108;
			view32[176>>2]=0xe2717193; view32[180>>2]=0xabd8d873; view32[184>>2]=0x62313153; view32[188>>2]=0x2a15153f;
			view32[192>>2]=0x0804040c; view32[196>>2]=0x95c7c752; view32[200>>2]=0x46232365; view32[204>>2]=0x9dc3c35e;
			view32[208>>2]=0x30181828; view32[212>>2]=0x379696a1; view32[216>>2]=0x0a05050f; view32[220>>2]=0x2f9a9ab5;
			view32[224>>2]=0x0e070709; view32[228>>2]=0x24121236; view32[232>>2]=0x1b80809b; view32[236>>2]=0xdfe2e23d;
			view32[240>>2]=0xcdebeb26; view32[244>>2]=0x4e272769; view32[248>>2]=0x7fb2b2cd; view32[252>>2]=0xea75759f;
			view32[256>>2]=0x1209091b; view32[260>>2]=0x1d83839e; view32[264>>2]=0x582c2c74; view32[268>>2]=0x341a1a2e;
			view32[272>>2]=0x361b1b2d; view32[276>>2]=0xdc6e6eb2; view32[280>>2]=0xb45a5aee; view32[284>>2]=0x5ba0a0fb;
			view32[288>>2]=0xa45252f6; view32[292>>2]=0x763b3b4d; view32[296>>2]=0xb7d6d661; view32[300>>2]=0x7db3b3ce;
			view32[304>>2]=0x5229297b; view32[308>>2]=0xdde3e33e; view32[312>>2]=0x5e2f2f71; view32[316>>2]=0x13848497;
			view32[320>>2]=0xa65353f5; view32[324>>2]=0xb9d1d168; view32[328>>2]=0x00000000; view32[332>>2]=0xc1eded2c;
			view32[336>>2]=0x40202060; view32[340>>2]=0xe3fcfc1f; view32[344>>2]=0x79b1b1c8; view32[348>>2]=0xb65b5bed;
			view32[352>>2]=0xd46a6abe; view32[356>>2]=0x8dcbcb46; view32[360>>2]=0x67bebed9; view32[364>>2]=0x7239394b;
			view32[368>>2]=0x944a4ade; view32[372>>2]=0x984c4cd4; view32[376>>2]=0xb05858e8; view32[380>>2]=0x85cfcf4a;
			view32[384>>2]=0xbbd0d06b; view32[388>>2]=0xc5efef2a; view32[392>>2]=0x4faaaae5; view32[396>>2]=0xedfbfb16;
			view32[400>>2]=0x864343c5; view32[404>>2]=0x9a4d4dd7; view32[408>>2]=0x66333355; view32[412>>2]=0x11858594;
			view32[416>>2]=0x8a4545cf; view32[420>>2]=0xe9f9f910; view32[424>>2]=0x04020206; view32[428>>2]=0xfe7f7f81;
			view32[432>>2]=0xa05050f0; view32[436>>2]=0x783c3c44; view32[440>>2]=0x259f9fba; view32[444>>2]=0x4ba8a8e3;
			view32[448>>2]=0xa25151f3; view32[452>>2]=0x5da3a3fe; view32[456>>2]=0x804040c0; view32[460>>2]=0x058f8f8a;
			view32[464>>2]=0x3f9292ad; view32[468>>2]=0x219d9dbc; view32[472>>2]=0x70383848; view32[476>>2]=0xf1f5f504;
			view32[480>>2]=0x63bcbcdf; view32[484>>2]=0x77b6b6c1; view32[488>>2]=0xafdada75; view32[492>>2]=0x42212163;
			view32[496>>2]=0x20101030; view32[500>>2]=0xe5ffff1a; view32[504>>2]=0xfdf3f30e; view32[508>>2]=0xbfd2d26d;
			view32[512>>2]=0x81cdcd4c; view32[516>>2]=0x180c0c14; view32[520>>2]=0x26131335; view32[524>>2]=0xc3ecec2f;
			view32[528>>2]=0xbe5f5fe1; view32[532>>2]=0x359797a2; view32[536>>2]=0x884444cc; view32[540>>2]=0x2e171739;
			view32[544>>2]=0x93c4c457; view32[548>>2]=0x55a7a7f2; view32[552>>2]=0xfc7e7e82; view32[556>>2]=0x7a3d3d47;
			view32[560>>2]=0xc86464ac; view32[564>>2]=0xba5d5de7; view32[568>>2]=0x3219192b; view32[572>>2]=0xe6737395;
			view32[576>>2]=0xc06060a0; view32[580>>2]=0x19818198; view32[584>>2]=0x9e4f4fd1; view32[588>>2]=0xa3dcdc7f;
			view32[592>>2]=0x44222266; view32[596>>2]=0x542a2a7e; view32[600>>2]=0x3b9090ab; view32[604>>2]=0x0b888883;
			view32[608>>2]=0x8c4646ca; view32[612>>2]=0xc7eeee29; view32[616>>2]=0x6bb8b8d3; view32[620>>2]=0x2814143c;
			view32[624>>2]=0xa7dede79; view32[628>>2]=0xbc5e5ee2; view32[632>>2]=0x160b0b1d; view32[636>>2]=0xaddbdb76;
			view32[640>>2]=0xdbe0e03b; view32[644>>2]=0x64323256; view32[648>>2]=0x743a3a4e; view32[652>>2]=0x140a0a1e;
			view32[656>>2]=0x924949db; view32[660>>2]=0x0c06060a; view32[664>>2]=0x4824246c; view32[668>>2]=0xb85c5ce4;
			view32[672>>2]=0x9fc2c25d; view32[676>>2]=0xbdd3d36e; view32[680>>2]=0x43acacef; view32[684>>2]=0xc46262a6;
			view32[688>>2]=0x399191a8; view32[692>>2]=0x319595a4; view32[696>>2]=0xd3e4e437; view32[700>>2]=0xf279798b;
			view32[704>>2]=0xd5e7e732; view32[708>>2]=0x8bc8c843; view32[712>>2]=0x6e373759; view32[716>>2]=0xda6d6db7;
			view32[720>>2]=0x018d8d8c; view32[724>>2]=0xb1d5d564; view32[728>>2]=0x9c4e4ed2; view32[732>>2]=0x49a9a9e0;
			view32[736>>2]=0xd86c6cb4; view32[740>>2]=0xac5656fa; view32[744>>2]=0xf3f4f407; view32[748>>2]=0xcfeaea25;
			view32[752>>2]=0xca6565af; view32[756>>2]=0xf47a7a8e; view32[760>>2]=0x47aeaee9; view32[764>>2]=0x10080818;
			view32[768>>2]=0x6fbabad5; view32[772>>2]=0xf0787888; view32[776>>2]=0x4a25256f; view32[780>>2]=0x5c2e2e72;
			view32[784>>2]=0x381c1c24; view32[788>>2]=0x57a6a6f1; view32[792>>2]=0x73b4b4c7; view32[796>>2]=0x97c6c651;
			view32[800>>2]=0xcbe8e823; view32[804>>2]=0xa1dddd7c; view32[808>>2]=0xe874749c; view32[812>>2]=0x3e1f1f21;
			view32[816>>2]=0x964b4bdd; view32[820>>2]=0x61bdbddc; view32[824>>2]=0x0d8b8b86; view32[828>>2]=0x0f8a8a85;
			view32[832>>2]=0xe0707090; view32[836>>2]=0x7c3e3e42; view32[840>>2]=0x71b5b5c4; view32[844>>2]=0xcc6666aa;
			view32[848>>2]=0x904848d8; view32[852>>2]=0x06030305; view32[856>>2]=0xf7f6f601; view32[860>>2]=0x1c0e0e12;
			view32[864>>2]=0xc26161a3; view32[868>>2]=0x6a35355f; view32[872>>2]=0xae5757f9; view32[876>>2]=0x69b9b9d0;
			view32[880>>2]=0x17868691; view32[884>>2]=0x99c1c158; view32[888>>2]=0x3a1d1d27; view32[892>>2]=0x279e9eb9;
			view32[896>>2]=0xd9e1e138; view32[900>>2]=0xebf8f813; view32[904>>2]=0x2b9898b3; view32[908>>2]=0x22111133;
			view32[912>>2]=0xd26969bb; view32[916>>2]=0xa9d9d970; view32[920>>2]=0x078e8e89; view32[924>>2]=0x339494a7;
			view32[928>>2]=0x2d9b9bb6; view32[932>>2]=0x3c1e1e22; view32[936>>2]=0x15878792; view32[940>>2]=0xc9e9e920;
			view32[944>>2]=0x87cece49; view32[948>>2]=0xaa5555ff; view32[952>>2]=0x50282878; view32[956>>2]=0xa5dfdf7a;
			view32[960>>2]=0x038c8c8f; view32[964>>2]=0x59a1a1f8; view32[968>>2]=0x09898980; view32[972>>2]=0x1a0d0d17;
			view32[976>>2]=0x65bfbfda; view32[980>>2]=0xd7e6e631; view32[984>>2]=0x844242c6; view32[988>>2]=0xd06868b8;
			view32[992>>2]=0x824141c3; view32[996>>2]=0x299999b0; view32[1000>>2]=0x5a2d2d77; view32[1004>>2]=0x1e0f0f11;
			view32[1008>>2]=0x7bb0b0cb; view32[1012>>2]=0xa85454fc; view32[1016>>2]=0x6dbbbbd6; view32[1020>>2]=0x2c16163a;

// Load the Te1 lookup table
			view32[1024>>2]=0xa5c66363; view32[1028>>2]=0x84f87c7c; view32[1032>>2]=0x99ee7777; view32[1036>>2]=0x8df67b7b;
			view32[1040>>2]=0x0dfff2f2; view32[1044>>2]=0xbdd66b6b; view32[1048>>2]=0xb1de6f6f; view32[1052>>2]=0x5491c5c5;
			view32[1056>>2]=0x50603030; view32[1060>>2]=0x03020101; view32[1064>>2]=0xa9ce6767; view32[1068>>2]=0x7d562b2b;
			view32[1072>>2]=0x19e7fefe; view32[1076>>2]=0x62b5d7d7; view32[1080>>2]=0xe64dabab; view32[1084>>2]=0x9aec7676;
			view32[1088>>2]=0x458fcaca; view32[1092>>2]=0x9d1f8282; view32[1096>>2]=0x4089c9c9; view32[1100>>2]=0x87fa7d7d;
			view32[1104>>2]=0x15effafa; view32[1108>>2]=0xebb25959; view32[1112>>2]=0xc98e4747; view32[1116>>2]=0x0bfbf0f0;
			view32[1120>>2]=0xec41adad; view32[1124>>2]=0x67b3d4d4; view32[1128>>2]=0xfd5fa2a2; view32[1132>>2]=0xea45afaf;
			view32[1136>>2]=0xbf239c9c; view32[1140>>2]=0xf753a4a4; view32[1144>>2]=0x96e47272; view32[1148>>2]=0x5b9bc0c0;
			view32[1152>>2]=0xc275b7b7; view32[1156>>2]=0x1ce1fdfd; view32[1160>>2]=0xae3d9393; view32[1164>>2]=0x6a4c2626;
			view32[1168>>2]=0x5a6c3636; view32[1172>>2]=0x417e3f3f; view32[1176>>2]=0x02f5f7f7; view32[1180>>2]=0x4f83cccc;
			view32[1184>>2]=0x5c683434; view32[1188>>2]=0xf451a5a5; view32[1192>>2]=0x34d1e5e5; view32[1196>>2]=0x08f9f1f1;
			view32[1200>>2]=0x93e27171; view32[1204>>2]=0x73abd8d8; view32[1208>>2]=0x53623131; view32[1212>>2]=0x3f2a1515;
			view32[1216>>2]=0x0c080404; view32[1220>>2]=0x5295c7c7; view32[1224>>2]=0x65462323; view32[1228>>2]=0x5e9dc3c3;
			view32[1232>>2]=0x28301818; view32[1236>>2]=0xa1379696; view32[1240>>2]=0x0f0a0505; view32[1244>>2]=0xb52f9a9a;
			view32[1248>>2]=0x090e0707; view32[1252>>2]=0x36241212; view32[1256>>2]=0x9b1b8080; view32[1260>>2]=0x3ddfe2e2;
			view32[1264>>2]=0x26cdebeb; view32[1268>>2]=0x694e2727; view32[1272>>2]=0xcd7fb2b2; view32[1276>>2]=0x9fea7575;
			view32[1280>>2]=0x1b120909; view32[1284>>2]=0x9e1d8383; view32[1288>>2]=0x74582c2c; view32[1292>>2]=0x2e341a1a;
			view32[1296>>2]=0x2d361b1b; view32[1300>>2]=0xb2dc6e6e; view32[1304>>2]=0xeeb45a5a; view32[1308>>2]=0xfb5ba0a0;
			view32[1312>>2]=0xf6a45252; view32[1316>>2]=0x4d763b3b; view32[1320>>2]=0x61b7d6d6; view32[1324>>2]=0xce7db3b3;
			view32[1328>>2]=0x7b522929; view32[1332>>2]=0x3edde3e3; view32[1336>>2]=0x715e2f2f; view32[1340>>2]=0x97138484;
			view32[1344>>2]=0xf5a65353; view32[1348>>2]=0x68b9d1d1; view32[1352>>2]=0x00000000; view32[1356>>2]=0x2cc1eded;
			view32[1360>>2]=0x60402020; view32[1364>>2]=0x1fe3fcfc; view32[1368>>2]=0xc879b1b1; view32[1372>>2]=0xedb65b5b;
			view32[1376>>2]=0xbed46a6a; view32[1380>>2]=0x468dcbcb; view32[1384>>2]=0xd967bebe; view32[1388>>2]=0x4b723939;
			view32[1392>>2]=0xde944a4a; view32[1396>>2]=0xd4984c4c; view32[1400>>2]=0xe8b05858; view32[1404>>2]=0x4a85cfcf;
			view32[1408>>2]=0x6bbbd0d0; view32[1412>>2]=0x2ac5efef; view32[1416>>2]=0xe54faaaa; view32[1420>>2]=0x16edfbfb;
			view32[1424>>2]=0xc5864343; view32[1428>>2]=0xd79a4d4d; view32[1432>>2]=0x55663333; view32[1436>>2]=0x94118585;
			view32[1440>>2]=0xcf8a4545; view32[1444>>2]=0x10e9f9f9; view32[1448>>2]=0x06040202; view32[1452>>2]=0x81fe7f7f;
			view32[1456>>2]=0xf0a05050; view32[1460>>2]=0x44783c3c; view32[1464>>2]=0xba259f9f; view32[1468>>2]=0xe34ba8a8;
			view32[1472>>2]=0xf3a25151; view32[1476>>2]=0xfe5da3a3; view32[1480>>2]=0xc0804040; view32[1484>>2]=0x8a058f8f;
			view32[1488>>2]=0xad3f9292; view32[1492>>2]=0xbc219d9d; view32[1496>>2]=0x48703838; view32[1500>>2]=0x04f1f5f5;
			view32[1504>>2]=0xdf63bcbc; view32[1508>>2]=0xc177b6b6; view32[1512>>2]=0x75afdada; view32[1516>>2]=0x63422121;
			view32[1520>>2]=0x30201010; view32[1524>>2]=0x1ae5ffff; view32[1528>>2]=0x0efdf3f3; view32[1532>>2]=0x6dbfd2d2;
			view32[1536>>2]=0x4c81cdcd; view32[1540>>2]=0x14180c0c; view32[1544>>2]=0x35261313; view32[1548>>2]=0x2fc3ecec;
			view32[1552>>2]=0xe1be5f5f; view32[1556>>2]=0xa2359797; view32[1560>>2]=0xcc884444; view32[1564>>2]=0x392e1717;
			view32[1568>>2]=0x5793c4c4; view32[1572>>2]=0xf255a7a7; view32[1576>>2]=0x82fc7e7e; view32[1580>>2]=0x477a3d3d;
			view32[1584>>2]=0xacc86464; view32[1588>>2]=0xe7ba5d5d; view32[1592>>2]=0x2b321919; view32[1596>>2]=0x95e67373;
			view32[1600>>2]=0xa0c06060; view32[1604>>2]=0x98198181; view32[1608>>2]=0xd19e4f4f; view32[1612>>2]=0x7fa3dcdc;
			view32[1616>>2]=0x66442222; view32[1620>>2]=0x7e542a2a; view32[1624>>2]=0xab3b9090; view32[1628>>2]=0x830b8888;
			view32[1632>>2]=0xca8c4646; view32[1636>>2]=0x29c7eeee; view32[1640>>2]=0xd36bb8b8; view32[1644>>2]=0x3c281414;
			view32[1648>>2]=0x79a7dede; view32[1652>>2]=0xe2bc5e5e; view32[1656>>2]=0x1d160b0b; view32[1660>>2]=0x76addbdb;
			view32[1664>>2]=0x3bdbe0e0; view32[1668>>2]=0x56643232; view32[1672>>2]=0x4e743a3a; view32[1676>>2]=0x1e140a0a;
			view32[1680>>2]=0xdb924949; view32[1684>>2]=0x0a0c0606; view32[1688>>2]=0x6c482424; view32[1692>>2]=0xe4b85c5c;
			view32[1696>>2]=0x5d9fc2c2; view32[1700>>2]=0x6ebdd3d3; view32[1704>>2]=0xef43acac; view32[1708>>2]=0xa6c46262;
			view32[1712>>2]=0xa8399191; view32[1716>>2]=0xa4319595; view32[1720>>2]=0x37d3e4e4; view32[1724>>2]=0x8bf27979;
			view32[1728>>2]=0x32d5e7e7; view32[1732>>2]=0x438bc8c8; view32[1736>>2]=0x596e3737; view32[1740>>2]=0xb7da6d6d;
			view32[1744>>2]=0x8c018d8d; view32[1748>>2]=0x64b1d5d5; view32[1752>>2]=0xd29c4e4e; view32[1756>>2]=0xe049a9a9;
			view32[1760>>2]=0xb4d86c6c; view32[1764>>2]=0xfaac5656; view32[1768>>2]=0x07f3f4f4; view32[1772>>2]=0x25cfeaea;
			view32[1776>>2]=0xafca6565; view32[1780>>2]=0x8ef47a7a; view32[1784>>2]=0xe947aeae; view32[1788>>2]=0x18100808;
			view32[1792>>2]=0xd56fbaba; view32[1796>>2]=0x88f07878; view32[1800>>2]=0x6f4a2525; view32[1804>>2]=0x725c2e2e;
			view32[1808>>2]=0x24381c1c; view32[1812>>2]=0xf157a6a6; view32[1816>>2]=0xc773b4b4; view32[1820>>2]=0x5197c6c6;
			view32[1824>>2]=0x23cbe8e8; view32[1828>>2]=0x7ca1dddd; view32[1832>>2]=0x9ce87474; view32[1836>>2]=0x213e1f1f;
			view32[1840>>2]=0xdd964b4b; view32[1844>>2]=0xdc61bdbd; view32[1848>>2]=0x860d8b8b; view32[1852>>2]=0x850f8a8a;
			view32[1856>>2]=0x90e07070; view32[1860>>2]=0x427c3e3e; view32[1864>>2]=0xc471b5b5; view32[1868>>2]=0xaacc6666;
			view32[1872>>2]=0xd8904848; view32[1876>>2]=0x05060303; view32[1880>>2]=0x01f7f6f6; view32[1884>>2]=0x121c0e0e;
			view32[1888>>2]=0xa3c26161; view32[1892>>2]=0x5f6a3535; view32[1896>>2]=0xf9ae5757; view32[1900>>2]=0xd069b9b9;
			view32[1904>>2]=0x91178686; view32[1908>>2]=0x5899c1c1; view32[1912>>2]=0x273a1d1d; view32[1916>>2]=0xb9279e9e;
			view32[1920>>2]=0x38d9e1e1; view32[1924>>2]=0x13ebf8f8; view32[1928>>2]=0xb32b9898; view32[1932>>2]=0x33221111;
			view32[1936>>2]=0xbbd26969; view32[1940>>2]=0x70a9d9d9; view32[1944>>2]=0x89078e8e; view32[1948>>2]=0xa7339494;
			view32[1952>>2]=0xb62d9b9b; view32[1956>>2]=0x223c1e1e; view32[1960>>2]=0x92158787; view32[1964>>2]=0x20c9e9e9;
			view32[1968>>2]=0x4987cece; view32[1972>>2]=0xffaa5555; view32[1976>>2]=0x78502828; view32[1980>>2]=0x7aa5dfdf;
			view32[1984>>2]=0x8f038c8c; view32[1988>>2]=0xf859a1a1; view32[1992>>2]=0x80098989; view32[1996>>2]=0x171a0d0d;
			view32[2000>>2]=0xda65bfbf; view32[2004>>2]=0x31d7e6e6; view32[2008>>2]=0xc6844242; view32[2012>>2]=0xb8d06868;
			view32[2016>>2]=0xc3824141; view32[2020>>2]=0xb0299999; view32[2024>>2]=0x775a2d2d; view32[2028>>2]=0x111e0f0f;
			view32[2032>>2]=0xcb7bb0b0; view32[2036>>2]=0xfca85454; view32[2040>>2]=0xd66dbbbb; view32[2044>>2]=0x3a2c1616;

// Load the Te2 lookup table
			view32[2048>>2]=0x63a5c663; view32[2052>>2]=0x7c84f87c; view32[2056>>2]=0x7799ee77; view32[2060>>2]=0x7b8df67b;
			view32[2064>>2]=0xf20dfff2; view32[2068>>2]=0x6bbdd66b; view32[2072>>2]=0x6fb1de6f; view32[2076>>2]=0xc55491c5;
			view32[2080>>2]=0x30506030; view32[2084>>2]=0x01030201; view32[2088>>2]=0x67a9ce67; view32[2092>>2]=0x2b7d562b;
			view32[2096>>2]=0xfe19e7fe; view32[2100>>2]=0xd762b5d7; view32[2104>>2]=0xabe64dab; view32[2108>>2]=0x769aec76;
			view32[2112>>2]=0xca458fca; view32[2116>>2]=0x829d1f82; view32[2120>>2]=0xc94089c9; view32[2124>>2]=0x7d87fa7d;
			view32[2128>>2]=0xfa15effa; view32[2132>>2]=0x59ebb259; view32[2136>>2]=0x47c98e47; view32[2140>>2]=0xf00bfbf0;
			view32[2144>>2]=0xadec41ad; view32[2148>>2]=0xd467b3d4; view32[2152>>2]=0xa2fd5fa2; view32[2156>>2]=0xafea45af;
			view32[2160>>2]=0x9cbf239c; view32[2164>>2]=0xa4f753a4; view32[2168>>2]=0x7296e472; view32[2172>>2]=0xc05b9bc0;
			view32[2176>>2]=0xb7c275b7; view32[2180>>2]=0xfd1ce1fd; view32[2184>>2]=0x93ae3d93; view32[2188>>2]=0x266a4c26;
			view32[2192>>2]=0x365a6c36; view32[2196>>2]=0x3f417e3f; view32[2200>>2]=0xf702f5f7; view32[2204>>2]=0xcc4f83cc;
			view32[2208>>2]=0x345c6834; view32[2212>>2]=0xa5f451a5; view32[2216>>2]=0xe534d1e5; view32[2220>>2]=0xf108f9f1;
			view32[2224>>2]=0x7193e271; view32[2228>>2]=0xd873abd8; view32[2232>>2]=0x31536231; view32[2236>>2]=0x153f2a15;
			view32[2240>>2]=0x040c0804; view32[2244>>2]=0xc75295c7; view32[2248>>2]=0x23654623; view32[2252>>2]=0xc35e9dc3;
			view32[2256>>2]=0x18283018; view32[2260>>2]=0x96a13796; view32[2264>>2]=0x050f0a05; view32[2268>>2]=0x9ab52f9a;
			view32[2272>>2]=0x07090e07; view32[2276>>2]=0x12362412; view32[2280>>2]=0x809b1b80; view32[2284>>2]=0xe23ddfe2;
			view32[2288>>2]=0xeb26cdeb; view32[2292>>2]=0x27694e27; view32[2296>>2]=0xb2cd7fb2; view32[2300>>2]=0x759fea75;
			view32[2304>>2]=0x091b1209; view32[2308>>2]=0x839e1d83; view32[2312>>2]=0x2c74582c; view32[2316>>2]=0x1a2e341a;
			view32[2320>>2]=0x1b2d361b; view32[2324>>2]=0x6eb2dc6e; view32[2328>>2]=0x5aeeb45a; view32[2332>>2]=0xa0fb5ba0;
			view32[2336>>2]=0x52f6a452; view32[2340>>2]=0x3b4d763b; view32[2344>>2]=0xd661b7d6; view32[2348>>2]=0xb3ce7db3;
			view32[2352>>2]=0x297b5229; view32[2356>>2]=0xe33edde3; view32[2360>>2]=0x2f715e2f; view32[2364>>2]=0x84971384;
			view32[2368>>2]=0x53f5a653; view32[2372>>2]=0xd168b9d1; view32[2376>>2]=0x00000000; view32[2380>>2]=0xed2cc1ed;
			view32[2384>>2]=0x20604020; view32[2388>>2]=0xfc1fe3fc; view32[2392>>2]=0xb1c879b1; view32[2396>>2]=0x5bedb65b;
			view32[2400>>2]=0x6abed46a; view32[2404>>2]=0xcb468dcb; view32[2408>>2]=0xbed967be; view32[2412>>2]=0x394b7239;
			view32[2416>>2]=0x4ade944a; view32[2420>>2]=0x4cd4984c; view32[2424>>2]=0x58e8b058; view32[2428>>2]=0xcf4a85cf;
			view32[2432>>2]=0xd06bbbd0; view32[2436>>2]=0xef2ac5ef; view32[2440>>2]=0xaae54faa; view32[2444>>2]=0xfb16edfb;
			view32[2448>>2]=0x43c58643; view32[2452>>2]=0x4dd79a4d; view32[2456>>2]=0x33556633; view32[2460>>2]=0x85941185;
			view32[2464>>2]=0x45cf8a45; view32[2468>>2]=0xf910e9f9; view32[2472>>2]=0x02060402; view32[2476>>2]=0x7f81fe7f;
			view32[2480>>2]=0x50f0a050; view32[2484>>2]=0x3c44783c; view32[2488>>2]=0x9fba259f; view32[2492>>2]=0xa8e34ba8;
			view32[2496>>2]=0x51f3a251; view32[2500>>2]=0xa3fe5da3; view32[2504>>2]=0x40c08040; view32[2508>>2]=0x8f8a058f;
			view32[2512>>2]=0x92ad3f92; view32[2516>>2]=0x9dbc219d; view32[2520>>2]=0x38487038; view32[2524>>2]=0xf504f1f5;
			view32[2528>>2]=0xbcdf63bc; view32[2532>>2]=0xb6c177b6; view32[2536>>2]=0xda75afda; view32[2540>>2]=0x21634221;
			view32[2544>>2]=0x10302010; view32[2548>>2]=0xff1ae5ff; view32[2552>>2]=0xf30efdf3; view32[2556>>2]=0xd26dbfd2;
			view32[2560>>2]=0xcd4c81cd; view32[2564>>2]=0x0c14180c; view32[2568>>2]=0x13352613; view32[2572>>2]=0xec2fc3ec;
			view32[2576>>2]=0x5fe1be5f; view32[2580>>2]=0x97a23597; view32[2584>>2]=0x44cc8844; view32[2588>>2]=0x17392e17;
			view32[2592>>2]=0xc45793c4; view32[2596>>2]=0xa7f255a7; view32[2600>>2]=0x7e82fc7e; view32[2604>>2]=0x3d477a3d;
			view32[2608>>2]=0x64acc864; view32[2612>>2]=0x5de7ba5d; view32[2616>>2]=0x192b3219; view32[2620>>2]=0x7395e673;
			view32[2624>>2]=0x60a0c060; view32[2628>>2]=0x81981981; view32[2632>>2]=0x4fd19e4f; view32[2636>>2]=0xdc7fa3dc;
			view32[2640>>2]=0x22664422; view32[2644>>2]=0x2a7e542a; view32[2648>>2]=0x90ab3b90; view32[2652>>2]=0x88830b88;
			view32[2656>>2]=0x46ca8c46; view32[2660>>2]=0xee29c7ee; view32[2664>>2]=0xb8d36bb8; view32[2668>>2]=0x143c2814;
			view32[2672>>2]=0xde79a7de; view32[2676>>2]=0x5ee2bc5e; view32[2680>>2]=0x0b1d160b; view32[2684>>2]=0xdb76addb;
			view32[2688>>2]=0xe03bdbe0; view32[2692>>2]=0x32566432; view32[2696>>2]=0x3a4e743a; view32[2700>>2]=0x0a1e140a;
			view32[2704>>2]=0x49db9249; view32[2708>>2]=0x060a0c06; view32[2712>>2]=0x246c4824; view32[2716>>2]=0x5ce4b85c;
			view32[2720>>2]=0xc25d9fc2; view32[2724>>2]=0xd36ebdd3; view32[2728>>2]=0xacef43ac; view32[2732>>2]=0x62a6c462;
			view32[2736>>2]=0x91a83991; view32[2740>>2]=0x95a43195; view32[2744>>2]=0xe437d3e4; view32[2748>>2]=0x798bf279;
			view32[2752>>2]=0xe732d5e7; view32[2756>>2]=0xc8438bc8; view32[2760>>2]=0x37596e37; view32[2764>>2]=0x6db7da6d;
			view32[2768>>2]=0x8d8c018d; view32[2772>>2]=0xd564b1d5; view32[2776>>2]=0x4ed29c4e; view32[2780>>2]=0xa9e049a9;
			view32[2784>>2]=0x6cb4d86c; view32[2788>>2]=0x56faac56; view32[2792>>2]=0xf407f3f4; view32[2796>>2]=0xea25cfea;
			view32[2800>>2]=0x65afca65; view32[2804>>2]=0x7a8ef47a; view32[2808>>2]=0xaee947ae; view32[2812>>2]=0x08181008;
			view32[2816>>2]=0xbad56fba; view32[2820>>2]=0x7888f078; view32[2824>>2]=0x256f4a25; view32[2828>>2]=0x2e725c2e;
			view32[2832>>2]=0x1c24381c; view32[2836>>2]=0xa6f157a6; view32[2840>>2]=0xb4c773b4; view32[2844>>2]=0xc65197c6;
			view32[2848>>2]=0xe823cbe8; view32[2852>>2]=0xdd7ca1dd; view32[2856>>2]=0x749ce874; view32[2860>>2]=0x1f213e1f;
			view32[2864>>2]=0x4bdd964b; view32[2868>>2]=0xbddc61bd; view32[2872>>2]=0x8b860d8b; view32[2876>>2]=0x8a850f8a;
			view32[2880>>2]=0x7090e070; view32[2884>>2]=0x3e427c3e; view32[2888>>2]=0xb5c471b5; view32[2892>>2]=0x66aacc66;
			view32[2896>>2]=0x48d89048; view32[2900>>2]=0x03050603; view32[2904>>2]=0xf601f7f6; view32[2908>>2]=0x0e121c0e;
			view32[2912>>2]=0x61a3c261; view32[2916>>2]=0x355f6a35; view32[2920>>2]=0x57f9ae57; view32[2924>>2]=0xb9d069b9;
			view32[2928>>2]=0x86911786; view32[2932>>2]=0xc15899c1; view32[2936>>2]=0x1d273a1d; view32[2940>>2]=0x9eb9279e;
			view32[2944>>2]=0xe138d9e1; view32[2948>>2]=0xf813ebf8; view32[2952>>2]=0x98b32b98; view32[2956>>2]=0x11332211;
			view32[2960>>2]=0x69bbd269; view32[2964>>2]=0xd970a9d9; view32[2968>>2]=0x8e89078e; view32[2972>>2]=0x94a73394;
			view32[2976>>2]=0x9bb62d9b; view32[2980>>2]=0x1e223c1e; view32[2984>>2]=0x87921587; view32[2988>>2]=0xe920c9e9;
			view32[2992>>2]=0xce4987ce; view32[2996>>2]=0x55ffaa55; view32[3000>>2]=0x28785028; view32[3004>>2]=0xdf7aa5df;
			view32[3008>>2]=0x8c8f038c; view32[3012>>2]=0xa1f859a1; view32[3016>>2]=0x89800989; view32[3020>>2]=0x0d171a0d;
			view32[3024>>2]=0xbfda65bf; view32[3028>>2]=0xe631d7e6; view32[3032>>2]=0x42c68442; view32[3036>>2]=0x68b8d068;
			view32[3040>>2]=0x41c38241; view32[3044>>2]=0x99b02999; view32[3048>>2]=0x2d775a2d; view32[3052>>2]=0x0f111e0f;
			view32[3056>>2]=0xb0cb7bb0; view32[3060>>2]=0x54fca854; view32[3064>>2]=0xbbd66dbb; view32[3068>>2]=0x163a2c16;

// Load the Te3 lookup table
			view32[3072>>2]=0x6363a5c6; view32[3076>>2]=0x7c7c84f8; view32[3080>>2]=0x777799ee; view32[3084>>2]=0x7b7b8df6;
			view32[3088>>2]=0xf2f20dff; view32[3092>>2]=0x6b6bbdd6; view32[3096>>2]=0x6f6fb1de; view32[3100>>2]=0xc5c55491;
			view32[3104>>2]=0x30305060; view32[3108>>2]=0x01010302; view32[3112>>2]=0x6767a9ce; view32[3116>>2]=0x2b2b7d56;
			view32[3120>>2]=0xfefe19e7; view32[3124>>2]=0xd7d762b5; view32[3128>>2]=0xababe64d; view32[3132>>2]=0x76769aec;
			view32[3136>>2]=0xcaca458f; view32[3140>>2]=0x82829d1f; view32[3144>>2]=0xc9c94089; view32[3148>>2]=0x7d7d87fa;
			view32[3152>>2]=0xfafa15ef; view32[3156>>2]=0x5959ebb2; view32[3160>>2]=0x4747c98e; view32[3164>>2]=0xf0f00bfb;
			view32[3168>>2]=0xadadec41; view32[3172>>2]=0xd4d467b3; view32[3176>>2]=0xa2a2fd5f; view32[3180>>2]=0xafafea45;
			view32[3184>>2]=0x9c9cbf23; view32[3188>>2]=0xa4a4f753; view32[3192>>2]=0x727296e4; view32[3196>>2]=0xc0c05b9b;
			view32[3200>>2]=0xb7b7c275; view32[3204>>2]=0xfdfd1ce1; view32[3208>>2]=0x9393ae3d; view32[3212>>2]=0x26266a4c;
			view32[3216>>2]=0x36365a6c; view32[3220>>2]=0x3f3f417e; view32[3224>>2]=0xf7f702f5; view32[3228>>2]=0xcccc4f83;
			view32[3232>>2]=0x34345c68; view32[3236>>2]=0xa5a5f451; view32[3240>>2]=0xe5e534d1; view32[3244>>2]=0xf1f108f9;
			view32[3248>>2]=0x717193e2; view32[3252>>2]=0xd8d873ab; view32[3256>>2]=0x31315362; view32[3260>>2]=0x15153f2a;
			view32[3264>>2]=0x04040c08; view32[3268>>2]=0xc7c75295; view32[3272>>2]=0x23236546; view32[3276>>2]=0xc3c35e9d;
			view32[3280>>2]=0x18182830; view32[3284>>2]=0x9696a137; view32[3288>>2]=0x05050f0a; view32[3292>>2]=0x9a9ab52f;
			view32[3296>>2]=0x0707090e; view32[3300>>2]=0x12123624; view32[3304>>2]=0x80809b1b; view32[3308>>2]=0xe2e23ddf;
			view32[3312>>2]=0xebeb26cd; view32[3316>>2]=0x2727694e; view32[3320>>2]=0xb2b2cd7f; view32[3324>>2]=0x75759fea;
			view32[3328>>2]=0x09091b12; view32[3332>>2]=0x83839e1d; view32[3336>>2]=0x2c2c7458; view32[3340>>2]=0x1a1a2e34;
			view32[3344>>2]=0x1b1b2d36; view32[3348>>2]=0x6e6eb2dc; view32[3352>>2]=0x5a5aeeb4; view32[3356>>2]=0xa0a0fb5b;
			view32[3360>>2]=0x5252f6a4; view32[3364>>2]=0x3b3b4d76; view32[3368>>2]=0xd6d661b7; view32[3372>>2]=0xb3b3ce7d;
			view32[3376>>2]=0x29297b52; view32[3380>>2]=0xe3e33edd; view32[3384>>2]=0x2f2f715e; view32[3388>>2]=0x84849713;
			view32[3392>>2]=0x5353f5a6; view32[3396>>2]=0xd1d168b9; view32[3400>>2]=0x00000000; view32[3404>>2]=0xeded2cc1;
			view32[3408>>2]=0x20206040; view32[3412>>2]=0xfcfc1fe3; view32[3416>>2]=0xb1b1c879; view32[3420>>2]=0x5b5bedb6;
			view32[3424>>2]=0x6a6abed4; view32[3428>>2]=0xcbcb468d; view32[3432>>2]=0xbebed967; view32[3436>>2]=0x39394b72;
			view32[3440>>2]=0x4a4ade94; view32[3444>>2]=0x4c4cd498; view32[3448>>2]=0x5858e8b0; view32[3452>>2]=0xcfcf4a85;
			view32[3456>>2]=0xd0d06bbb; view32[3460>>2]=0xefef2ac5; view32[3464>>2]=0xaaaae54f; view32[3468>>2]=0xfbfb16ed;
			view32[3472>>2]=0x4343c586; view32[3476>>2]=0x4d4dd79a; view32[3480>>2]=0x33335566; view32[3484>>2]=0x85859411;
			view32[3488>>2]=0x4545cf8a; view32[3492>>2]=0xf9f910e9; view32[3496>>2]=0x02020604; view32[3500>>2]=0x7f7f81fe;
			view32[3504>>2]=0x5050f0a0; view32[3508>>2]=0x3c3c4478; view32[3512>>2]=0x9f9fba25; view32[3516>>2]=0xa8a8e34b;
			view32[3520>>2]=0x5151f3a2; view32[3524>>2]=0xa3a3fe5d; view32[3528>>2]=0x4040c080; view32[3532>>2]=0x8f8f8a05;
			view32[3536>>2]=0x9292ad3f; view32[3540>>2]=0x9d9dbc21; view32[3544>>2]=0x38384870; view32[3548>>2]=0xf5f504f1;
			view32[3552>>2]=0xbcbcdf63; view32[3556>>2]=0xb6b6c177; view32[3560>>2]=0xdada75af; view32[3564>>2]=0x21216342;
			view32[3568>>2]=0x10103020; view32[3572>>2]=0xffff1ae5; view32[3576>>2]=0xf3f30efd; view32[3580>>2]=0xd2d26dbf;
			view32[3584>>2]=0xcdcd4c81; view32[3588>>2]=0x0c0c1418; view32[3592>>2]=0x13133526; view32[3596>>2]=0xecec2fc3;
			view32[3600>>2]=0x5f5fe1be; view32[3604>>2]=0x9797a235; view32[3608>>2]=0x4444cc88; view32[3612>>2]=0x1717392e;
			view32[3616>>2]=0xc4c45793; view32[3620>>2]=0xa7a7f255; view32[3624>>2]=0x7e7e82fc; view32[3628>>2]=0x3d3d477a;
			view32[3632>>2]=0x6464acc8; view32[3636>>2]=0x5d5de7ba; view32[3640>>2]=0x19192b32; view32[3644>>2]=0x737395e6;
			view32[3648>>2]=0x6060a0c0; view32[3652>>2]=0x81819819; view32[3656>>2]=0x4f4fd19e; view32[3660>>2]=0xdcdc7fa3;
			view32[3664>>2]=0x22226644; view32[3668>>2]=0x2a2a7e54; view32[3672>>2]=0x9090ab3b; view32[3676>>2]=0x8888830b;
			view32[3680>>2]=0x4646ca8c; view32[3684>>2]=0xeeee29c7; view32[3688>>2]=0xb8b8d36b; view32[3692>>2]=0x14143c28;
			view32[3696>>2]=0xdede79a7; view32[3700>>2]=0x5e5ee2bc; view32[3704>>2]=0x0b0b1d16; view32[3708>>2]=0xdbdb76ad;
			view32[3712>>2]=0xe0e03bdb; view32[3716>>2]=0x32325664; view32[3720>>2]=0x3a3a4e74; view32[3724>>2]=0x0a0a1e14;
			view32[3728>>2]=0x4949db92; view32[3732>>2]=0x06060a0c; view32[3736>>2]=0x24246c48; view32[3740>>2]=0x5c5ce4b8;
			view32[3744>>2]=0xc2c25d9f; view32[3748>>2]=0xd3d36ebd; view32[3752>>2]=0xacacef43; view32[3756>>2]=0x6262a6c4;
			view32[3760>>2]=0x9191a839; view32[3764>>2]=0x9595a431; view32[3768>>2]=0xe4e437d3; view32[3772>>2]=0x79798bf2;
			view32[3776>>2]=0xe7e732d5; view32[3780>>2]=0xc8c8438b; view32[3784>>2]=0x3737596e; view32[3788>>2]=0x6d6db7da;
			view32[3792>>2]=0x8d8d8c01; view32[3796>>2]=0xd5d564b1; view32[3800>>2]=0x4e4ed29c; view32[3804>>2]=0xa9a9e049;
			view32[3808>>2]=0x6c6cb4d8; view32[3812>>2]=0x5656faac; view32[3816>>2]=0xf4f407f3; view32[3820>>2]=0xeaea25cf;
			view32[3824>>2]=0x6565afca; view32[3828>>2]=0x7a7a8ef4; view32[3832>>2]=0xaeaee947; view32[3836>>2]=0x08081810;
			view32[3840>>2]=0xbabad56f; view32[3844>>2]=0x787888f0; view32[3848>>2]=0x25256f4a; view32[3852>>2]=0x2e2e725c;
			view32[3856>>2]=0x1c1c2438; view32[3860>>2]=0xa6a6f157; view32[3864>>2]=0xb4b4c773; view32[3868>>2]=0xc6c65197;
			view32[3872>>2]=0xe8e823cb; view32[3876>>2]=0xdddd7ca1; view32[3880>>2]=0x74749ce8; view32[3884>>2]=0x1f1f213e;
			view32[3888>>2]=0x4b4bdd96; view32[3892>>2]=0xbdbddc61; view32[3896>>2]=0x8b8b860d; view32[3900>>2]=0x8a8a850f;
			view32[3904>>2]=0x707090e0; view32[3908>>2]=0x3e3e427c; view32[3912>>2]=0xb5b5c471; view32[3916>>2]=0x6666aacc;
			view32[3920>>2]=0x4848d890; view32[3924>>2]=0x03030506; view32[3928>>2]=0xf6f601f7; view32[3932>>2]=0x0e0e121c;
			view32[3936>>2]=0x6161a3c2; view32[3940>>2]=0x35355f6a; view32[3944>>2]=0x5757f9ae; view32[3948>>2]=0xb9b9d069;
			view32[3952>>2]=0x86869117; view32[3956>>2]=0xc1c15899; view32[3960>>2]=0x1d1d273a; view32[3964>>2]=0x9e9eb927;
			view32[3968>>2]=0xe1e138d9; view32[3972>>2]=0xf8f813eb; view32[3976>>2]=0x9898b32b; view32[3980>>2]=0x11113322;
			view32[3984>>2]=0x6969bbd2; view32[3988>>2]=0xd9d970a9; view32[3992>>2]=0x8e8e8907; view32[3996>>2]=0x9494a733;
			view32[4000>>2]=0x9b9bb62d; view32[4004>>2]=0x1e1e223c; view32[4008>>2]=0x87879215; view32[4012>>2]=0xe9e920c9;
			view32[4016>>2]=0xcece4987; view32[4020>>2]=0x5555ffaa; view32[4024>>2]=0x28287850; view32[4028>>2]=0xdfdf7aa5;
			view32[4032>>2]=0x8c8c8f03; view32[4036>>2]=0xa1a1f859; view32[4040>>2]=0x89898009; view32[4044>>2]=0x0d0d171a;
			view32[4048>>2]=0xbfbfda65; view32[4052>>2]=0xe6e631d7; view32[4056>>2]=0x4242c684; view32[4060>>2]=0x6868b8d0;
			view32[4064>>2]=0x4141c382; view32[4068>>2]=0x9999b029; view32[4072>>2]=0x2d2d775a; view32[4076>>2]=0x0f0f111e;
			view32[4080>>2]=0xb0b0cb7b; view32[4084>>2]=0x5454fca8; view32[4088>>2]=0xbbbbd66d; view32[4092>>2]=0x16163a2c;

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

// Load the Td0 lookup table
			view32[5120>>2]=0x51f4a750; view32[5124>>2]=0x7e416553; view32[5128>>2]=0x1a17a4c3; view32[5132>>2]=0x3a275e96;
			view32[5136>>2]=0x3bab6bcb; view32[5140>>2]=0x1f9d45f1; view32[5144>>2]=0xacfa58ab; view32[5148>>2]=0x4be30393;
			view32[5152>>2]=0x2030fa55; view32[5156>>2]=0xad766df6; view32[5160>>2]=0x88cc7691; view32[5164>>2]=0xf5024c25;
			view32[5168>>2]=0x4fe5d7fc; view32[5172>>2]=0xc52acbd7; view32[5176>>2]=0x26354480; view32[5180>>2]=0xb562a38f;
			view32[5184>>2]=0xdeb15a49; view32[5188>>2]=0x25ba1b67; view32[5192>>2]=0x45ea0e98; view32[5196>>2]=0x5dfec0e1;
			view32[5200>>2]=0xc32f7502; view32[5204>>2]=0x814cf012; view32[5208>>2]=0x8d4697a3; view32[5212>>2]=0x6bd3f9c6;
			view32[5216>>2]=0x038f5fe7; view32[5220>>2]=0x15929c95; view32[5224>>2]=0xbf6d7aeb; view32[5228>>2]=0x955259da;
			view32[5232>>2]=0xd4be832d; view32[5236>>2]=0x587421d3; view32[5240>>2]=0x49e06929; view32[5244>>2]=0x8ec9c844;
			view32[5248>>2]=0x75c2896a; view32[5252>>2]=0xf48e7978; view32[5256>>2]=0x99583e6b; view32[5260>>2]=0x27b971dd;
			view32[5264>>2]=0xbee14fb6; view32[5268>>2]=0xf088ad17; view32[5272>>2]=0xc920ac66; view32[5276>>2]=0x7dce3ab4;
			view32[5280>>2]=0x63df4a18; view32[5284>>2]=0xe51a3182; view32[5288>>2]=0x97513360; view32[5292>>2]=0x62537f45;
			view32[5296>>2]=0xb16477e0; view32[5300>>2]=0xbb6bae84; view32[5304>>2]=0xfe81a01c; view32[5308>>2]=0xf9082b94;
			view32[5312>>2]=0x70486858; view32[5316>>2]=0x8f45fd19; view32[5320>>2]=0x94de6c87; view32[5324>>2]=0x527bf8b7;
			view32[5328>>2]=0xab73d323; view32[5332>>2]=0x724b02e2; view32[5336>>2]=0xe31f8f57; view32[5340>>2]=0x6655ab2a;
			view32[5344>>2]=0xb2eb2807; view32[5348>>2]=0x2fb5c203; view32[5352>>2]=0x86c57b9a; view32[5356>>2]=0xd33708a5;
			view32[5360>>2]=0x302887f2; view32[5364>>2]=0x23bfa5b2; view32[5368>>2]=0x02036aba; view32[5372>>2]=0xed16825c;
			view32[5376>>2]=0x8acf1c2b; view32[5380>>2]=0xa779b492; view32[5384>>2]=0xf307f2f0; view32[5388>>2]=0x4e69e2a1;
			view32[5392>>2]=0x65daf4cd; view32[5396>>2]=0x0605bed5; view32[5400>>2]=0xd134621f; view32[5404>>2]=0xc4a6fe8a;
			view32[5408>>2]=0x342e539d; view32[5412>>2]=0xa2f355a0; view32[5416>>2]=0x058ae132; view32[5420>>2]=0xa4f6eb75;
			view32[5424>>2]=0x0b83ec39; view32[5428>>2]=0x4060efaa; view32[5432>>2]=0x5e719f06; view32[5436>>2]=0xbd6e1051;
			view32[5440>>2]=0x3e218af9; view32[5444>>2]=0x96dd063d; view32[5448>>2]=0xdd3e05ae; view32[5452>>2]=0x4de6bd46;
			view32[5456>>2]=0x91548db5; view32[5460>>2]=0x71c45d05; view32[5464>>2]=0x0406d46f; view32[5468>>2]=0x605015ff;
			view32[5472>>2]=0x1998fb24; view32[5476>>2]=0xd6bde997; view32[5480>>2]=0x894043cc; view32[5484>>2]=0x67d99e77;
			view32[5488>>2]=0xb0e842bd; view32[5492>>2]=0x07898b88; view32[5496>>2]=0xe7195b38; view32[5500>>2]=0x79c8eedb;
			view32[5504>>2]=0xa17c0a47; view32[5508>>2]=0x7c420fe9; view32[5512>>2]=0xf8841ec9; view32[5516>>2]=0x00000000;
			view32[5520>>2]=0x09808683; view32[5524>>2]=0x322bed48; view32[5528>>2]=0x1e1170ac; view32[5532>>2]=0x6c5a724e;
			view32[5536>>2]=0xfd0efffb; view32[5540>>2]=0x0f853856; view32[5544>>2]=0x3daed51e; view32[5548>>2]=0x362d3927;
			view32[5552>>2]=0x0a0fd964; view32[5556>>2]=0x685ca621; view32[5560>>2]=0x9b5b54d1; view32[5564>>2]=0x24362e3a;
			view32[5568>>2]=0x0c0a67b1; view32[5572>>2]=0x9357e70f; view32[5576>>2]=0xb4ee96d2; view32[5580>>2]=0x1b9b919e;
			view32[5584>>2]=0x80c0c54f; view32[5588>>2]=0x61dc20a2; view32[5592>>2]=0x5a774b69; view32[5596>>2]=0x1c121a16;
			view32[5600>>2]=0xe293ba0a; view32[5604>>2]=0xc0a02ae5; view32[5608>>2]=0x3c22e043; view32[5612>>2]=0x121b171d;
			view32[5616>>2]=0x0e090d0b; view32[5620>>2]=0xf28bc7ad; view32[5624>>2]=0x2db6a8b9; view32[5628>>2]=0x141ea9c8;
			view32[5632>>2]=0x57f11985; view32[5636>>2]=0xaf75074c; view32[5640>>2]=0xee99ddbb; view32[5644>>2]=0xa37f60fd;
			view32[5648>>2]=0xf701269f; view32[5652>>2]=0x5c72f5bc; view32[5656>>2]=0x44663bc5; view32[5660>>2]=0x5bfb7e34;
			view32[5664>>2]=0x8b432976; view32[5668>>2]=0xcb23c6dc; view32[5672>>2]=0xb6edfc68; view32[5676>>2]=0xb8e4f163;
			view32[5680>>2]=0xd731dcca; view32[5684>>2]=0x42638510; view32[5688>>2]=0x13972240; view32[5692>>2]=0x84c61120;
			view32[5696>>2]=0x854a247d; view32[5700>>2]=0xd2bb3df8; view32[5704>>2]=0xaef93211; view32[5708>>2]=0xc729a16d;
			view32[5712>>2]=0x1d9e2f4b; view32[5716>>2]=0xdcb230f3; view32[5720>>2]=0x0d8652ec; view32[5724>>2]=0x77c1e3d0;
			view32[5728>>2]=0x2bb3166c; view32[5732>>2]=0xa970b999; view32[5736>>2]=0x119448fa; view32[5740>>2]=0x47e96422;
			view32[5744>>2]=0xa8fc8cc4; view32[5748>>2]=0xa0f03f1a; view32[5752>>2]=0x567d2cd8; view32[5756>>2]=0x223390ef;
			view32[5760>>2]=0x87494ec7; view32[5764>>2]=0xd938d1c1; view32[5768>>2]=0x8ccaa2fe; view32[5772>>2]=0x98d40b36;
			view32[5776>>2]=0xa6f581cf; view32[5780>>2]=0xa57ade28; view32[5784>>2]=0xdab78e26; view32[5788>>2]=0x3fadbfa4;
			view32[5792>>2]=0x2c3a9de4; view32[5796>>2]=0x5078920d; view32[5800>>2]=0x6a5fcc9b; view32[5804>>2]=0x547e4662;
			view32[5808>>2]=0xf68d13c2; view32[5812>>2]=0x90d8b8e8; view32[5816>>2]=0x2e39f75e; view32[5820>>2]=0x82c3aff5;
			view32[5824>>2]=0x9f5d80be; view32[5828>>2]=0x69d0937c; view32[5832>>2]=0x6fd52da9; view32[5836>>2]=0xcf2512b3;
			view32[5840>>2]=0xc8ac993b; view32[5844>>2]=0x10187da7; view32[5848>>2]=0xe89c636e; view32[5852>>2]=0xdb3bbb7b;
			view32[5856>>2]=0xcd267809; view32[5860>>2]=0x6e5918f4; view32[5864>>2]=0xec9ab701; view32[5868>>2]=0x834f9aa8;
			view32[5872>>2]=0xe6956e65; view32[5876>>2]=0xaaffe67e; view32[5880>>2]=0x21bccf08; view32[5884>>2]=0xef15e8e6;
			view32[5888>>2]=0xbae79bd9; view32[5892>>2]=0x4a6f36ce; view32[5896>>2]=0xea9f09d4; view32[5900>>2]=0x29b07cd6;
			view32[5904>>2]=0x31a4b2af; view32[5908>>2]=0x2a3f2331; view32[5912>>2]=0xc6a59430; view32[5916>>2]=0x35a266c0;
			view32[5920>>2]=0x744ebc37; view32[5924>>2]=0xfc82caa6; view32[5928>>2]=0xe090d0b0; view32[5932>>2]=0x33a7d815;
			view32[5936>>2]=0xf104984a; view32[5940>>2]=0x41ecdaf7; view32[5944>>2]=0x7fcd500e; view32[5948>>2]=0x1791f62f;
			view32[5952>>2]=0x764dd68d; view32[5956>>2]=0x43efb04d; view32[5960>>2]=0xccaa4d54; view32[5964>>2]=0xe49604df;
			view32[5968>>2]=0x9ed1b5e3; view32[5972>>2]=0x4c6a881b; view32[5976>>2]=0xc12c1fb8; view32[5980>>2]=0x4665517f;
			view32[5984>>2]=0x9d5eea04; view32[5988>>2]=0x018c355d; view32[5992>>2]=0xfa877473; view32[5996>>2]=0xfb0b412e;
			view32[6000>>2]=0xb3671d5a; view32[6004>>2]=0x92dbd252; view32[6008>>2]=0xe9105633; view32[6012>>2]=0x6dd64713;
			view32[6016>>2]=0x9ad7618c; view32[6020>>2]=0x37a10c7a; view32[6024>>2]=0x59f8148e; view32[6028>>2]=0xeb133c89;
			view32[6032>>2]=0xcea927ee; view32[6036>>2]=0xb761c935; view32[6040>>2]=0xe11ce5ed; view32[6044>>2]=0x7a47b13c;
			view32[6048>>2]=0x9cd2df59; view32[6052>>2]=0x55f2733f; view32[6056>>2]=0x1814ce79; view32[6060>>2]=0x73c737bf;
			view32[6064>>2]=0x53f7cdea; view32[6068>>2]=0x5ffdaa5b; view32[6072>>2]=0xdf3d6f14; view32[6076>>2]=0x7844db86;
			view32[6080>>2]=0xcaaff381; view32[6084>>2]=0xb968c43e; view32[6088>>2]=0x3824342c; view32[6092>>2]=0xc2a3405f;
			view32[6096>>2]=0x161dc372; view32[6100>>2]=0xbce2250c; view32[6104>>2]=0x283c498b; view32[6108>>2]=0xff0d9541;
			view32[6112>>2]=0x39a80171; view32[6116>>2]=0x080cb3de; view32[6120>>2]=0xd8b4e49c; view32[6124>>2]=0x6456c190;
			view32[6128>>2]=0x7bcb8461; view32[6132>>2]=0xd532b670; view32[6136>>2]=0x486c5c74; view32[6140>>2]=0xd0b85742;

// Load the Td1 lookup table
			view32[6144>>2]=0x5051f4a7; view32[6148>>2]=0x537e4165; view32[6152>>2]=0xc31a17a4; view32[6156>>2]=0x963a275e;
			view32[6160>>2]=0xcb3bab6b; view32[6164>>2]=0xf11f9d45; view32[6168>>2]=0xabacfa58; view32[6172>>2]=0x934be303;
			view32[6176>>2]=0x552030fa; view32[6180>>2]=0xf6ad766d; view32[6184>>2]=0x9188cc76; view32[6188>>2]=0x25f5024c;
			view32[6192>>2]=0xfc4fe5d7; view32[6196>>2]=0xd7c52acb; view32[6200>>2]=0x80263544; view32[6204>>2]=0x8fb562a3;
			view32[6208>>2]=0x49deb15a; view32[6212>>2]=0x6725ba1b; view32[6216>>2]=0x9845ea0e; view32[6220>>2]=0xe15dfec0;
			view32[6224>>2]=0x02c32f75; view32[6228>>2]=0x12814cf0; view32[6232>>2]=0xa38d4697; view32[6236>>2]=0xc66bd3f9;
			view32[6240>>2]=0xe7038f5f; view32[6244>>2]=0x9515929c; view32[6248>>2]=0xebbf6d7a; view32[6252>>2]=0xda955259;
			view32[6256>>2]=0x2dd4be83; view32[6260>>2]=0xd3587421; view32[6264>>2]=0x2949e069; view32[6268>>2]=0x448ec9c8;
			view32[6272>>2]=0x6a75c289; view32[6276>>2]=0x78f48e79; view32[6280>>2]=0x6b99583e; view32[6284>>2]=0xdd27b971;
			view32[6288>>2]=0xb6bee14f; view32[6292>>2]=0x17f088ad; view32[6296>>2]=0x66c920ac; view32[6300>>2]=0xb47dce3a;
			view32[6304>>2]=0x1863df4a; view32[6308>>2]=0x82e51a31; view32[6312>>2]=0x60975133; view32[6316>>2]=0x4562537f;
			view32[6320>>2]=0xe0b16477; view32[6324>>2]=0x84bb6bae; view32[6328>>2]=0x1cfe81a0; view32[6332>>2]=0x94f9082b;
			view32[6336>>2]=0x58704868; view32[6340>>2]=0x198f45fd; view32[6344>>2]=0x8794de6c; view32[6348>>2]=0xb7527bf8;
			view32[6352>>2]=0x23ab73d3; view32[6356>>2]=0xe2724b02; view32[6360>>2]=0x57e31f8f; view32[6364>>2]=0x2a6655ab;
			view32[6368>>2]=0x07b2eb28; view32[6372>>2]=0x032fb5c2; view32[6376>>2]=0x9a86c57b; view32[6380>>2]=0xa5d33708;
			view32[6384>>2]=0xf2302887; view32[6388>>2]=0xb223bfa5; view32[6392>>2]=0xba02036a; view32[6396>>2]=0x5ced1682;
			view32[6400>>2]=0x2b8acf1c; view32[6404>>2]=0x92a779b4; view32[6408>>2]=0xf0f307f2; view32[6412>>2]=0xa14e69e2;
			view32[6416>>2]=0xcd65daf4; view32[6420>>2]=0xd50605be; view32[6424>>2]=0x1fd13462; view32[6428>>2]=0x8ac4a6fe;
			view32[6432>>2]=0x9d342e53; view32[6436>>2]=0xa0a2f355; view32[6440>>2]=0x32058ae1; view32[6444>>2]=0x75a4f6eb;
			view32[6448>>2]=0x390b83ec; view32[6452>>2]=0xaa4060ef; view32[6456>>2]=0x065e719f; view32[6460>>2]=0x51bd6e10;
			view32[6464>>2]=0xf93e218a; view32[6468>>2]=0x3d96dd06; view32[6472>>2]=0xaedd3e05; view32[6476>>2]=0x464de6bd;
			view32[6480>>2]=0xb591548d; view32[6484>>2]=0x0571c45d; view32[6488>>2]=0x6f0406d4; view32[6492>>2]=0xff605015;
			view32[6496>>2]=0x241998fb; view32[6500>>2]=0x97d6bde9; view32[6504>>2]=0xcc894043; view32[6508>>2]=0x7767d99e;
			view32[6512>>2]=0xbdb0e842; view32[6516>>2]=0x8807898b; view32[6520>>2]=0x38e7195b; view32[6524>>2]=0xdb79c8ee;
			view32[6528>>2]=0x47a17c0a; view32[6532>>2]=0xe97c420f; view32[6536>>2]=0xc9f8841e; view32[6540>>2]=0x00000000;
			view32[6544>>2]=0x83098086; view32[6548>>2]=0x48322bed; view32[6552>>2]=0xac1e1170; view32[6556>>2]=0x4e6c5a72;
			view32[6560>>2]=0xfbfd0eff; view32[6564>>2]=0x560f8538; view32[6568>>2]=0x1e3daed5; view32[6572>>2]=0x27362d39;
			view32[6576>>2]=0x640a0fd9; view32[6580>>2]=0x21685ca6; view32[6584>>2]=0xd19b5b54; view32[6588>>2]=0x3a24362e;
			view32[6592>>2]=0xb10c0a67; view32[6596>>2]=0x0f9357e7; view32[6600>>2]=0xd2b4ee96; view32[6604>>2]=0x9e1b9b91;
			view32[6608>>2]=0x4f80c0c5; view32[6612>>2]=0xa261dc20; view32[6616>>2]=0x695a774b; view32[6620>>2]=0x161c121a;
			view32[6624>>2]=0x0ae293ba; view32[6628>>2]=0xe5c0a02a; view32[6632>>2]=0x433c22e0; view32[6636>>2]=0x1d121b17;
			view32[6640>>2]=0x0b0e090d; view32[6644>>2]=0xadf28bc7; view32[6648>>2]=0xb92db6a8; view32[6652>>2]=0xc8141ea9;
			view32[6656>>2]=0x8557f119; view32[6660>>2]=0x4caf7507; view32[6664>>2]=0xbbee99dd; view32[6668>>2]=0xfda37f60;
			view32[6672>>2]=0x9ff70126; view32[6676>>2]=0xbc5c72f5; view32[6680>>2]=0xc544663b; view32[6684>>2]=0x345bfb7e;
			view32[6688>>2]=0x768b4329; view32[6692>>2]=0xdccb23c6; view32[6696>>2]=0x68b6edfc; view32[6700>>2]=0x63b8e4f1;
			view32[6704>>2]=0xcad731dc; view32[6708>>2]=0x10426385; view32[6712>>2]=0x40139722; view32[6716>>2]=0x2084c611;
			view32[6720>>2]=0x7d854a24; view32[6724>>2]=0xf8d2bb3d; view32[6728>>2]=0x11aef932; view32[6732>>2]=0x6dc729a1;
			view32[6736>>2]=0x4b1d9e2f; view32[6740>>2]=0xf3dcb230; view32[6744>>2]=0xec0d8652; view32[6748>>2]=0xd077c1e3;
			view32[6752>>2]=0x6c2bb316; view32[6756>>2]=0x99a970b9; view32[6760>>2]=0xfa119448; view32[6764>>2]=0x2247e964;
			view32[6768>>2]=0xc4a8fc8c; view32[6772>>2]=0x1aa0f03f; view32[6776>>2]=0xd8567d2c; view32[6780>>2]=0xef223390;
			view32[6784>>2]=0xc787494e; view32[6788>>2]=0xc1d938d1; view32[6792>>2]=0xfe8ccaa2; view32[6796>>2]=0x3698d40b;
			view32[6800>>2]=0xcfa6f581; view32[6804>>2]=0x28a57ade; view32[6808>>2]=0x26dab78e; view32[6812>>2]=0xa43fadbf;
			view32[6816>>2]=0xe42c3a9d; view32[6820>>2]=0x0d507892; view32[6824>>2]=0x9b6a5fcc; view32[6828>>2]=0x62547e46;
			view32[6832>>2]=0xc2f68d13; view32[6836>>2]=0xe890d8b8; view32[6840>>2]=0x5e2e39f7; view32[6844>>2]=0xf582c3af;
			view32[6848>>2]=0xbe9f5d80; view32[6852>>2]=0x7c69d093; view32[6856>>2]=0xa96fd52d; view32[6860>>2]=0xb3cf2512;
			view32[6864>>2]=0x3bc8ac99; view32[6868>>2]=0xa710187d; view32[6872>>2]=0x6ee89c63; view32[6876>>2]=0x7bdb3bbb;
			view32[6880>>2]=0x09cd2678; view32[6884>>2]=0xf46e5918; view32[6888>>2]=0x01ec9ab7; view32[6892>>2]=0xa8834f9a;
			view32[6896>>2]=0x65e6956e; view32[6900>>2]=0x7eaaffe6; view32[6904>>2]=0x0821bccf; view32[6908>>2]=0xe6ef15e8;
			view32[6912>>2]=0xd9bae79b; view32[6916>>2]=0xce4a6f36; view32[6920>>2]=0xd4ea9f09; view32[6924>>2]=0xd629b07c;
			view32[6928>>2]=0xaf31a4b2; view32[6932>>2]=0x312a3f23; view32[6936>>2]=0x30c6a594; view32[6940>>2]=0xc035a266;
			view32[6944>>2]=0x37744ebc; view32[6948>>2]=0xa6fc82ca; view32[6952>>2]=0xb0e090d0; view32[6956>>2]=0x1533a7d8;
			view32[6960>>2]=0x4af10498; view32[6964>>2]=0xf741ecda; view32[6968>>2]=0x0e7fcd50; view32[6972>>2]=0x2f1791f6;
			view32[6976>>2]=0x8d764dd6; view32[6980>>2]=0x4d43efb0; view32[6984>>2]=0x54ccaa4d; view32[6988>>2]=0xdfe49604;
			view32[6992>>2]=0xe39ed1b5; view32[6996>>2]=0x1b4c6a88; view32[7000>>2]=0xb8c12c1f; view32[7004>>2]=0x7f466551;
			view32[7008>>2]=0x049d5eea; view32[7012>>2]=0x5d018c35; view32[7016>>2]=0x73fa8774; view32[7020>>2]=0x2efb0b41;
			view32[7024>>2]=0x5ab3671d; view32[7028>>2]=0x5292dbd2; view32[7032>>2]=0x33e91056; view32[7036>>2]=0x136dd647;
			view32[7040>>2]=0x8c9ad761; view32[7044>>2]=0x7a37a10c; view32[7048>>2]=0x8e59f814; view32[7052>>2]=0x89eb133c;
			view32[7056>>2]=0xeecea927; view32[7060>>2]=0x35b761c9; view32[7064>>2]=0xede11ce5; view32[7068>>2]=0x3c7a47b1;
			view32[7072>>2]=0x599cd2df; view32[7076>>2]=0x3f55f273; view32[7080>>2]=0x791814ce; view32[7084>>2]=0xbf73c737;
			view32[7088>>2]=0xea53f7cd; view32[7092>>2]=0x5b5ffdaa; view32[7096>>2]=0x14df3d6f; view32[7100>>2]=0x867844db;
			view32[7104>>2]=0x81caaff3; view32[7108>>2]=0x3eb968c4; view32[7112>>2]=0x2c382434; view32[7116>>2]=0x5fc2a340;
			view32[7120>>2]=0x72161dc3; view32[7124>>2]=0x0cbce225; view32[7128>>2]=0x8b283c49; view32[7132>>2]=0x41ff0d95;
			view32[7136>>2]=0x7139a801; view32[7140>>2]=0xde080cb3; view32[7144>>2]=0x9cd8b4e4; view32[7148>>2]=0x906456c1;
			view32[7152>>2]=0x617bcb84; view32[7156>>2]=0x70d532b6; view32[7160>>2]=0x74486c5c; view32[7164>>2]=0x42d0b857;

// Load the Td2 lookup table
			view32[7168>>2]=0xa75051f4; view32[7172>>2]=0x65537e41; view32[7176>>2]=0xa4c31a17; view32[7180>>2]=0x5e963a27;
			view32[7184>>2]=0x6bcb3bab; view32[7188>>2]=0x45f11f9d; view32[7192>>2]=0x58abacfa; view32[7196>>2]=0x03934be3;
			view32[7200>>2]=0xfa552030; view32[7204>>2]=0x6df6ad76; view32[7208>>2]=0x769188cc; view32[7212>>2]=0x4c25f502;
			view32[7216>>2]=0xd7fc4fe5; view32[7220>>2]=0xcbd7c52a; view32[7224>>2]=0x44802635; view32[7228>>2]=0xa38fb562;
			view32[7232>>2]=0x5a49deb1; view32[7236>>2]=0x1b6725ba; view32[7240>>2]=0x0e9845ea; view32[7244>>2]=0xc0e15dfe;
			view32[7248>>2]=0x7502c32f; view32[7252>>2]=0xf012814c; view32[7256>>2]=0x97a38d46; view32[7260>>2]=0xf9c66bd3;
			view32[7264>>2]=0x5fe7038f; view32[7268>>2]=0x9c951592; view32[7272>>2]=0x7aebbf6d; view32[7276>>2]=0x59da9552;
			view32[7280>>2]=0x832dd4be; view32[7284>>2]=0x21d35874; view32[7288>>2]=0x692949e0; view32[7292>>2]=0xc8448ec9;
			view32[7296>>2]=0x896a75c2; view32[7300>>2]=0x7978f48e; view32[7304>>2]=0x3e6b9958; view32[7308>>2]=0x71dd27b9;
			view32[7312>>2]=0x4fb6bee1; view32[7316>>2]=0xad17f088; view32[7320>>2]=0xac66c920; view32[7324>>2]=0x3ab47dce;
			view32[7328>>2]=0x4a1863df; view32[7332>>2]=0x3182e51a; view32[7336>>2]=0x33609751; view32[7340>>2]=0x7f456253;
			view32[7344>>2]=0x77e0b164; view32[7348>>2]=0xae84bb6b; view32[7352>>2]=0xa01cfe81; view32[7356>>2]=0x2b94f908;
			view32[7360>>2]=0x68587048; view32[7364>>2]=0xfd198f45; view32[7368>>2]=0x6c8794de; view32[7372>>2]=0xf8b7527b;
			view32[7376>>2]=0xd323ab73; view32[7380>>2]=0x02e2724b; view32[7384>>2]=0x8f57e31f; view32[7388>>2]=0xab2a6655;
			view32[7392>>2]=0x2807b2eb; view32[7396>>2]=0xc2032fb5; view32[7400>>2]=0x7b9a86c5; view32[7404>>2]=0x08a5d337;
			view32[7408>>2]=0x87f23028; view32[7412>>2]=0xa5b223bf; view32[7416>>2]=0x6aba0203; view32[7420>>2]=0x825ced16;
			view32[7424>>2]=0x1c2b8acf; view32[7428>>2]=0xb492a779; view32[7432>>2]=0xf2f0f307; view32[7436>>2]=0xe2a14e69;
			view32[7440>>2]=0xf4cd65da; view32[7444>>2]=0xbed50605; view32[7448>>2]=0x621fd134; view32[7452>>2]=0xfe8ac4a6;
			view32[7456>>2]=0x539d342e; view32[7460>>2]=0x55a0a2f3; view32[7464>>2]=0xe132058a; view32[7468>>2]=0xeb75a4f6;
			view32[7472>>2]=0xec390b83; view32[7476>>2]=0xefaa4060; view32[7480>>2]=0x9f065e71; view32[7484>>2]=0x1051bd6e;
			view32[7488>>2]=0x8af93e21; view32[7492>>2]=0x063d96dd; view32[7496>>2]=0x05aedd3e; view32[7500>>2]=0xbd464de6;
			view32[7504>>2]=0x8db59154; view32[7508>>2]=0x5d0571c4; view32[7512>>2]=0xd46f0406; view32[7516>>2]=0x15ff6050;
			view32[7520>>2]=0xfb241998; view32[7524>>2]=0xe997d6bd; view32[7528>>2]=0x43cc8940; view32[7532>>2]=0x9e7767d9;
			view32[7536>>2]=0x42bdb0e8; view32[7540>>2]=0x8b880789; view32[7544>>2]=0x5b38e719; view32[7548>>2]=0xeedb79c8;
			view32[7552>>2]=0x0a47a17c; view32[7556>>2]=0x0fe97c42; view32[7560>>2]=0x1ec9f884; view32[7564>>2]=0x00000000;
			view32[7568>>2]=0x86830980; view32[7572>>2]=0xed48322b; view32[7576>>2]=0x70ac1e11; view32[7580>>2]=0x724e6c5a;
			view32[7584>>2]=0xfffbfd0e; view32[7588>>2]=0x38560f85; view32[7592>>2]=0xd51e3dae; view32[7596>>2]=0x3927362d;
			view32[7600>>2]=0xd9640a0f; view32[7604>>2]=0xa621685c; view32[7608>>2]=0x54d19b5b; view32[7612>>2]=0x2e3a2436;
			view32[7616>>2]=0x67b10c0a; view32[7620>>2]=0xe70f9357; view32[7624>>2]=0x96d2b4ee; view32[7628>>2]=0x919e1b9b;
			view32[7632>>2]=0xc54f80c0; view32[7636>>2]=0x20a261dc; view32[7640>>2]=0x4b695a77; view32[7644>>2]=0x1a161c12;
			view32[7648>>2]=0xba0ae293; view32[7652>>2]=0x2ae5c0a0; view32[7656>>2]=0xe0433c22; view32[7660>>2]=0x171d121b;
			view32[7664>>2]=0x0d0b0e09; view32[7668>>2]=0xc7adf28b; view32[7672>>2]=0xa8b92db6; view32[7676>>2]=0xa9c8141e;
			view32[7680>>2]=0x198557f1; view32[7684>>2]=0x074caf75; view32[7688>>2]=0xddbbee99; view32[7692>>2]=0x60fda37f;
			view32[7696>>2]=0x269ff701; view32[7700>>2]=0xf5bc5c72; view32[7704>>2]=0x3bc54466; view32[7708>>2]=0x7e345bfb;
			view32[7712>>2]=0x29768b43; view32[7716>>2]=0xc6dccb23; view32[7720>>2]=0xfc68b6ed; view32[7724>>2]=0xf163b8e4;
			view32[7728>>2]=0xdccad731; view32[7732>>2]=0x85104263; view32[7736>>2]=0x22401397; view32[7740>>2]=0x112084c6;
			view32[7744>>2]=0x247d854a; view32[7748>>2]=0x3df8d2bb; view32[7752>>2]=0x3211aef9; view32[7756>>2]=0xa16dc729;
			view32[7760>>2]=0x2f4b1d9e; view32[7764>>2]=0x30f3dcb2; view32[7768>>2]=0x52ec0d86; view32[7772>>2]=0xe3d077c1;
			view32[7776>>2]=0x166c2bb3; view32[7780>>2]=0xb999a970; view32[7784>>2]=0x48fa1194; view32[7788>>2]=0x642247e9;
			view32[7792>>2]=0x8cc4a8fc; view32[7796>>2]=0x3f1aa0f0; view32[7800>>2]=0x2cd8567d; view32[7804>>2]=0x90ef2233;
			view32[7808>>2]=0x4ec78749; view32[7812>>2]=0xd1c1d938; view32[7816>>2]=0xa2fe8cca; view32[7820>>2]=0x0b3698d4;
			view32[7824>>2]=0x81cfa6f5; view32[7828>>2]=0xde28a57a; view32[7832>>2]=0x8e26dab7; view32[7836>>2]=0xbfa43fad;
			view32[7840>>2]=0x9de42c3a; view32[7844>>2]=0x920d5078; view32[7848>>2]=0xcc9b6a5f; view32[7852>>2]=0x4662547e;
			view32[7856>>2]=0x13c2f68d; view32[7860>>2]=0xb8e890d8; view32[7864>>2]=0xf75e2e39; view32[7868>>2]=0xaff582c3;
			view32[7872>>2]=0x80be9f5d; view32[7876>>2]=0x937c69d0; view32[7880>>2]=0x2da96fd5; view32[7884>>2]=0x12b3cf25;
			view32[7888>>2]=0x993bc8ac; view32[7892>>2]=0x7da71018; view32[7896>>2]=0x636ee89c; view32[7900>>2]=0xbb7bdb3b;
			view32[7904>>2]=0x7809cd26; view32[7908>>2]=0x18f46e59; view32[7912>>2]=0xb701ec9a; view32[7916>>2]=0x9aa8834f;
			view32[7920>>2]=0x6e65e695; view32[7924>>2]=0xe67eaaff; view32[7928>>2]=0xcf0821bc; view32[7932>>2]=0xe8e6ef15;
			view32[7936>>2]=0x9bd9bae7; view32[7940>>2]=0x36ce4a6f; view32[7944>>2]=0x09d4ea9f; view32[7948>>2]=0x7cd629b0;
			view32[7952>>2]=0xb2af31a4; view32[7956>>2]=0x23312a3f; view32[7960>>2]=0x9430c6a5; view32[7964>>2]=0x66c035a2;
			view32[7968>>2]=0xbc37744e; view32[7972>>2]=0xcaa6fc82; view32[7976>>2]=0xd0b0e090; view32[7980>>2]=0xd81533a7;
			view32[7984>>2]=0x984af104; view32[7988>>2]=0xdaf741ec; view32[7992>>2]=0x500e7fcd; view32[7996>>2]=0xf62f1791;
			view32[8000>>2]=0xd68d764d; view32[8004>>2]=0xb04d43ef; view32[8008>>2]=0x4d54ccaa; view32[8012>>2]=0x04dfe496;
			view32[8016>>2]=0xb5e39ed1; view32[8020>>2]=0x881b4c6a; view32[8024>>2]=0x1fb8c12c; view32[8028>>2]=0x517f4665;
			view32[8032>>2]=0xea049d5e; view32[8036>>2]=0x355d018c; view32[8040>>2]=0x7473fa87; view32[8044>>2]=0x412efb0b;
			view32[8048>>2]=0x1d5ab367; view32[8052>>2]=0xd25292db; view32[8056>>2]=0x5633e910; view32[8060>>2]=0x47136dd6;
			view32[8064>>2]=0x618c9ad7; view32[8068>>2]=0x0c7a37a1; view32[8072>>2]=0x148e59f8; view32[8076>>2]=0x3c89eb13;
			view32[8080>>2]=0x27eecea9; view32[8084>>2]=0xc935b761; view32[8088>>2]=0xe5ede11c; view32[8092>>2]=0xb13c7a47;
			view32[8096>>2]=0xdf599cd2; view32[8100>>2]=0x733f55f2; view32[8104>>2]=0xce791814; view32[8108>>2]=0x37bf73c7;
			view32[8112>>2]=0xcdea53f7; view32[8116>>2]=0xaa5b5ffd; view32[8120>>2]=0x6f14df3d; view32[8124>>2]=0xdb867844;
			view32[8128>>2]=0xf381caaf; view32[8132>>2]=0xc43eb968; view32[8136>>2]=0x342c3824; view32[8140>>2]=0x405fc2a3;
			view32[8144>>2]=0xc372161d; view32[8148>>2]=0x250cbce2; view32[8152>>2]=0x498b283c; view32[8156>>2]=0x9541ff0d;
			view32[8160>>2]=0x017139a8; view32[8164>>2]=0xb3de080c; view32[8168>>2]=0xe49cd8b4; view32[8172>>2]=0xc1906456;
			view32[8176>>2]=0x84617bcb; view32[8180>>2]=0xb670d532; view32[8184>>2]=0x5c74486c; view32[8188>>2]=0x5742d0b8;

// Load the Td3 lookup table
			view32[8192>>2]=0xf4a75051; view32[8196>>2]=0x4165537e; view32[8200>>2]=0x17a4c31a; view32[8204>>2]=0x275e963a;
			view32[8208>>2]=0xab6bcb3b; view32[8212>>2]=0x9d45f11f; view32[8216>>2]=0xfa58abac; view32[8220>>2]=0xe303934b;
			view32[8224>>2]=0x30fa5520; view32[8228>>2]=0x766df6ad; view32[8232>>2]=0xcc769188; view32[8236>>2]=0x024c25f5;
			view32[8240>>2]=0xe5d7fc4f; view32[8244>>2]=0x2acbd7c5; view32[8248>>2]=0x35448026; view32[8252>>2]=0x62a38fb5;
			view32[8256>>2]=0xb15a49de; view32[8260>>2]=0xba1b6725; view32[8264>>2]=0xea0e9845; view32[8268>>2]=0xfec0e15d;
			view32[8272>>2]=0x2f7502c3; view32[8276>>2]=0x4cf01281; view32[8280>>2]=0x4697a38d; view32[8284>>2]=0xd3f9c66b;
			view32[8288>>2]=0x8f5fe703; view32[8292>>2]=0x929c9515; view32[8296>>2]=0x6d7aebbf; view32[8300>>2]=0x5259da95;
			view32[8304>>2]=0xbe832dd4; view32[8308>>2]=0x7421d358; view32[8312>>2]=0xe0692949; view32[8316>>2]=0xc9c8448e;
			view32[8320>>2]=0xc2896a75; view32[8324>>2]=0x8e7978f4; view32[8328>>2]=0x583e6b99; view32[8332>>2]=0xb971dd27;
			view32[8336>>2]=0xe14fb6be; view32[8340>>2]=0x88ad17f0; view32[8344>>2]=0x20ac66c9; view32[8348>>2]=0xce3ab47d;
			view32[8352>>2]=0xdf4a1863; view32[8356>>2]=0x1a3182e5; view32[8360>>2]=0x51336097; view32[8364>>2]=0x537f4562;
			view32[8368>>2]=0x6477e0b1; view32[8372>>2]=0x6bae84bb; view32[8376>>2]=0x81a01cfe; view32[8380>>2]=0x082b94f9;
			view32[8384>>2]=0x48685870; view32[8388>>2]=0x45fd198f; view32[8392>>2]=0xde6c8794; view32[8396>>2]=0x7bf8b752;
			view32[8400>>2]=0x73d323ab; view32[8404>>2]=0x4b02e272; view32[8408>>2]=0x1f8f57e3; view32[8412>>2]=0x55ab2a66;
			view32[8416>>2]=0xeb2807b2; view32[8420>>2]=0xb5c2032f; view32[8424>>2]=0xc57b9a86; view32[8428>>2]=0x3708a5d3;
			view32[8432>>2]=0x2887f230; view32[8436>>2]=0xbfa5b223; view32[8440>>2]=0x036aba02; view32[8444>>2]=0x16825ced;
			view32[8448>>2]=0xcf1c2b8a; view32[8452>>2]=0x79b492a7; view32[8456>>2]=0x07f2f0f3; view32[8460>>2]=0x69e2a14e;
			view32[8464>>2]=0xdaf4cd65; view32[8468>>2]=0x05bed506; view32[8472>>2]=0x34621fd1; view32[8476>>2]=0xa6fe8ac4;
			view32[8480>>2]=0x2e539d34; view32[8484>>2]=0xf355a0a2; view32[8488>>2]=0x8ae13205; view32[8492>>2]=0xf6eb75a4;
			view32[8496>>2]=0x83ec390b; view32[8500>>2]=0x60efaa40; view32[8504>>2]=0x719f065e; view32[8508>>2]=0x6e1051bd;
			view32[8512>>2]=0x218af93e; view32[8516>>2]=0xdd063d96; view32[8520>>2]=0x3e05aedd; view32[8524>>2]=0xe6bd464d;
			view32[8528>>2]=0x548db591; view32[8532>>2]=0xc45d0571; view32[8536>>2]=0x06d46f04; view32[8540>>2]=0x5015ff60;
			view32[8544>>2]=0x98fb2419; view32[8548>>2]=0xbde997d6; view32[8552>>2]=0x4043cc89; view32[8556>>2]=0xd99e7767;
			view32[8560>>2]=0xe842bdb0; view32[8564>>2]=0x898b8807; view32[8568>>2]=0x195b38e7; view32[8572>>2]=0xc8eedb79;
			view32[8576>>2]=0x7c0a47a1; view32[8580>>2]=0x420fe97c; view32[8584>>2]=0x841ec9f8; view32[8588>>2]=0x00000000;
			view32[8592>>2]=0x80868309; view32[8596>>2]=0x2bed4832; view32[8600>>2]=0x1170ac1e; view32[8604>>2]=0x5a724e6c;
			view32[8608>>2]=0x0efffbfd; view32[8612>>2]=0x8538560f; view32[8616>>2]=0xaed51e3d; view32[8620>>2]=0x2d392736;
			view32[8624>>2]=0x0fd9640a; view32[8628>>2]=0x5ca62168; view32[8632>>2]=0x5b54d19b; view32[8636>>2]=0x362e3a24;
			view32[8640>>2]=0x0a67b10c; view32[8644>>2]=0x57e70f93; view32[8648>>2]=0xee96d2b4; view32[8652>>2]=0x9b919e1b;
			view32[8656>>2]=0xc0c54f80; view32[8660>>2]=0xdc20a261; view32[8664>>2]=0x774b695a; view32[8668>>2]=0x121a161c;
			view32[8672>>2]=0x93ba0ae2; view32[8676>>2]=0xa02ae5c0; view32[8680>>2]=0x22e0433c; view32[8684>>2]=0x1b171d12;
			view32[8688>>2]=0x090d0b0e; view32[8692>>2]=0x8bc7adf2; view32[8696>>2]=0xb6a8b92d; view32[8700>>2]=0x1ea9c814;
			view32[8704>>2]=0xf1198557; view32[8708>>2]=0x75074caf; view32[8712>>2]=0x99ddbbee; view32[8716>>2]=0x7f60fda3;
			view32[8720>>2]=0x01269ff7; view32[8724>>2]=0x72f5bc5c; view32[8728>>2]=0x663bc544; view32[8732>>2]=0xfb7e345b;
			view32[8736>>2]=0x4329768b; view32[8740>>2]=0x23c6dccb; view32[8744>>2]=0xedfc68b6; view32[8748>>2]=0xe4f163b8;
			view32[8752>>2]=0x31dccad7; view32[8756>>2]=0x63851042; view32[8760>>2]=0x97224013; view32[8764>>2]=0xc6112084;
			view32[8768>>2]=0x4a247d85; view32[8772>>2]=0xbb3df8d2; view32[8776>>2]=0xf93211ae; view32[8780>>2]=0x29a16dc7;
			view32[8784>>2]=0x9e2f4b1d; view32[8788>>2]=0xb230f3dc; view32[8792>>2]=0x8652ec0d; view32[8796>>2]=0xc1e3d077;
			view32[8800>>2]=0xb3166c2b; view32[8804>>2]=0x70b999a9; view32[8808>>2]=0x9448fa11; view32[8812>>2]=0xe9642247;
			view32[8816>>2]=0xfc8cc4a8; view32[8820>>2]=0xf03f1aa0; view32[8824>>2]=0x7d2cd856; view32[8828>>2]=0x3390ef22;
			view32[8832>>2]=0x494ec787; view32[8836>>2]=0x38d1c1d9; view32[8840>>2]=0xcaa2fe8c; view32[8844>>2]=0xd40b3698;
			view32[8848>>2]=0xf581cfa6; view32[8852>>2]=0x7ade28a5; view32[8856>>2]=0xb78e26da; view32[8860>>2]=0xadbfa43f;
			view32[8864>>2]=0x3a9de42c; view32[8868>>2]=0x78920d50; view32[8872>>2]=0x5fcc9b6a; view32[8876>>2]=0x7e466254;
			view32[8880>>2]=0x8d13c2f6; view32[8884>>2]=0xd8b8e890; view32[8888>>2]=0x39f75e2e; view32[8892>>2]=0xc3aff582;
			view32[8896>>2]=0x5d80be9f; view32[8900>>2]=0xd0937c69; view32[8904>>2]=0xd52da96f; view32[8908>>2]=0x2512b3cf;
			view32[8912>>2]=0xac993bc8; view32[8916>>2]=0x187da710; view32[8920>>2]=0x9c636ee8; view32[8924>>2]=0x3bbb7bdb;
			view32[8928>>2]=0x267809cd; view32[8932>>2]=0x5918f46e; view32[8936>>2]=0x9ab701ec; view32[8940>>2]=0x4f9aa883;
			view32[8944>>2]=0x956e65e6; view32[8948>>2]=0xffe67eaa; view32[8952>>2]=0xbccf0821; view32[8956>>2]=0x15e8e6ef;
			view32[8960>>2]=0xe79bd9ba; view32[8964>>2]=0x6f36ce4a; view32[8968>>2]=0x9f09d4ea; view32[8972>>2]=0xb07cd629;
			view32[8976>>2]=0xa4b2af31; view32[8980>>2]=0x3f23312a; view32[8984>>2]=0xa59430c6; view32[8988>>2]=0xa266c035;
			view32[8992>>2]=0x4ebc3774; view32[8996>>2]=0x82caa6fc; view32[9000>>2]=0x90d0b0e0; view32[9004>>2]=0xa7d81533;
			view32[9008>>2]=0x04984af1; view32[9012>>2]=0xecdaf741; view32[9016>>2]=0xcd500e7f; view32[9020>>2]=0x91f62f17;
			view32[9024>>2]=0x4dd68d76; view32[9028>>2]=0xefb04d43; view32[9032>>2]=0xaa4d54cc; view32[9036>>2]=0x9604dfe4;
			view32[9040>>2]=0xd1b5e39e; view32[9044>>2]=0x6a881b4c; view32[9048>>2]=0x2c1fb8c1; view32[9052>>2]=0x65517f46;
			view32[9056>>2]=0x5eea049d; view32[9060>>2]=0x8c355d01; view32[9064>>2]=0x877473fa; view32[9068>>2]=0x0b412efb;
			view32[9072>>2]=0x671d5ab3; view32[9076>>2]=0xdbd25292; view32[9080>>2]=0x105633e9; view32[9084>>2]=0xd647136d;
			view32[9088>>2]=0xd7618c9a; view32[9092>>2]=0xa10c7a37; view32[9096>>2]=0xf8148e59; view32[9100>>2]=0x133c89eb;
			view32[9104>>2]=0xa927eece; view32[9108>>2]=0x61c935b7; view32[9112>>2]=0x1ce5ede1; view32[9116>>2]=0x47b13c7a;
			view32[9120>>2]=0xd2df599c; view32[9124>>2]=0xf2733f55; view32[9128>>2]=0x14ce7918; view32[9132>>2]=0xc737bf73;
			view32[9136>>2]=0xf7cdea53; view32[9140>>2]=0xfdaa5b5f; view32[9144>>2]=0x3d6f14df; view32[9148>>2]=0x44db8678;
			view32[9152>>2]=0xaff381ca; view32[9156>>2]=0x68c43eb9; view32[9160>>2]=0x24342c38; view32[9164>>2]=0xa3405fc2;
			view32[9168>>2]=0x1dc37216; view32[9172>>2]=0xe2250cbc; view32[9176>>2]=0x3c498b28; view32[9180>>2]=0x0d9541ff;
			view32[9184>>2]=0xa8017139; view32[9188>>2]=0x0cb3de08; view32[9192>>2]=0xb4e49cd8; view32[9196>>2]=0x56c19064;
			view32[9200>>2]=0xcb84617b; view32[9204>>2]=0x32b670d5; view32[9208>>2]=0x6c5c7448; view32[9212>>2]=0xb85742d0;

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

// Load the rcon lookup table
			view32[10240>>2]=0x01000000; view32[10244>>2]=0x02000000; view32[10248>>2]=0x04000000; view32[10252>>2]=0x08000000;
			view32[10256>>2]=0x10000000; view32[10260>>2]=0x20000000; view32[10264>>2]=0x40000000; view32[10268>>2]=0x80000000;
			view32[10272>>2]=0x1B000000; view32[10276>>2]=0x36000000;
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

			view32[(rk     ) >> 2] = btow((key     )  )|0; // 0
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

					/* temp is an int-pointer but a byte pointer is needed. Shift it. */
					view32[(rk + 32) >> 2] = ( // 8
						(view32[rk >> 2]) ^
						(view32[(Te4 + (((temp >> 16) & 0xff) << 2)) >> 2] & 0xff000000) ^
						(view32[(Te4 + (((temp >>  8) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
						(view32[(Te4 + (((temp      ) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
						(view32[(Te4 + (((temp >> 24)       ) << 2)) >> 2] & 0x000000ff) ^
						(view32[(rcon + (i << 2)) >> 2])
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
						(view32[(Te4 + (((temp >> 24)       ) << 2)) >> 2] & 0xff000000) ^
						(view32[(Te4 + (((temp >> 16) & 0xff) << 2)) >> 2] & 0x00ff0000) ^
						(view32[(Te4 + (((temp >>  8) & 0xff) << 2)) >> 2] & 0x0000ff00) ^
						(view32[(Te4 + (((temp      ) & 0xff) << 2)) >> 2] & 0x000000ff)
					)|0;

					view32[(rk + 52) >> 2] = (view32[(rk + 20) >> 2] ^ view32[(rk + 48) >> 2])|0; // 13
					view32[(rk + 56) >> 2] = (view32[(rk + 24) >> 2] ^ view32[(rk + 52) >> 2])|0; // 14
					view32[(rk + 60) >> 2] = (view32[(rk + 28) >> 2] ^ view32[(rk + 56) >> 2])|0; // 15

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

	function testEncrypt() {
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
	}

	return {
		"encrypt": encrypt,
		"decrypt": decrypt,
		"testEncrypt": testEncrypt
	}

}();
