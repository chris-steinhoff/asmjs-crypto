/**
 * User: chris
 * Date: 9/7/13
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

		var view8  = new stdlib.Uint8Array(heap);
		var view32 = new stdlib.Uint32Array(heap);
		var Te0  = new stdlib.Uint32Array(heap,     0, 256);
		var Te1  = new stdlib.Uint32Array(heap,  1024, 256);
		var Te2  = new stdlib.Uint32Array(heap,  2048, 256);
		var Te3  = new stdlib.Uint32Array(heap,  3072, 256);
		var Te4  = new stdlib.Uint32Array(heap,  4096, 256);
		/*var Td0  = new stdlib.Uint32Array(heap,  5120, 256);
		var Td1  = new stdlib.Uint32Array(heap,  6144, 256);
		var Td2  = new stdlib.Uint32Array(heap,  7168, 256);
		var Td3  = new stdlib.Uint32Array(heap,  8192, 256);
		var Td4  = new stdlib.Uint32Array(heap,  9216, 256);*/
		var rcon = new stdlib.Uint32Array(heap, 10240,  10);

		function init() {
// Load the Te0 lookup table
Te0[0]=0xc66363a5; Te0[1]=0xf87c7c84; Te0[2]=0xee777799; Te0[3]=0xf67b7b8d;
Te0[4]=0xfff2f20d; Te0[5]=0xd66b6bbd; Te0[6]=0xde6f6fb1; Te0[7]=0x91c5c554;
Te0[8]=0x60303050; Te0[9]=0x02010103; Te0[10]=0xce6767a9; Te0[11]=0x562b2b7d;
Te0[12]=0xe7fefe19; Te0[13]=0xb5d7d762; Te0[14]=0x4dababe6; Te0[15]=0xec76769a;
Te0[16]=0x8fcaca45; Te0[17]=0x1f82829d; Te0[18]=0x89c9c940; Te0[19]=0xfa7d7d87;
Te0[20]=0xeffafa15; Te0[21]=0xb25959eb; Te0[22]=0x8e4747c9; Te0[23]=0xfbf0f00b;
Te0[24]=0x41adadec; Te0[25]=0xb3d4d467; Te0[26]=0x5fa2a2fd; Te0[27]=0x45afafea;
Te0[28]=0x239c9cbf; Te0[29]=0x53a4a4f7; Te0[30]=0xe4727296; Te0[31]=0x9bc0c05b;
Te0[32]=0x75b7b7c2; Te0[33]=0xe1fdfd1c; Te0[34]=0x3d9393ae; Te0[35]=0x4c26266a;
Te0[36]=0x6c36365a; Te0[37]=0x7e3f3f41; Te0[38]=0xf5f7f702; Te0[39]=0x83cccc4f;
Te0[40]=0x6834345c; Te0[41]=0x51a5a5f4; Te0[42]=0xd1e5e534; Te0[43]=0xf9f1f108;
Te0[44]=0xe2717193; Te0[45]=0xabd8d873; Te0[46]=0x62313153; Te0[47]=0x2a15153f;
Te0[48]=0x0804040c; Te0[49]=0x95c7c752; Te0[50]=0x46232365; Te0[51]=0x9dc3c35e;
Te0[52]=0x30181828; Te0[53]=0x379696a1; Te0[54]=0x0a05050f; Te0[55]=0x2f9a9ab5;
Te0[56]=0x0e070709; Te0[57]=0x24121236; Te0[58]=0x1b80809b; Te0[59]=0xdfe2e23d;
Te0[60]=0xcdebeb26; Te0[61]=0x4e272769; Te0[62]=0x7fb2b2cd; Te0[63]=0xea75759f;
Te0[64]=0x1209091b; Te0[65]=0x1d83839e; Te0[66]=0x582c2c74; Te0[67]=0x341a1a2e;
Te0[68]=0x361b1b2d; Te0[69]=0xdc6e6eb2; Te0[70]=0xb45a5aee; Te0[71]=0x5ba0a0fb;
Te0[72]=0xa45252f6; Te0[73]=0x763b3b4d; Te0[74]=0xb7d6d661; Te0[75]=0x7db3b3ce;
Te0[76]=0x5229297b; Te0[77]=0xdde3e33e; Te0[78]=0x5e2f2f71; Te0[79]=0x13848497;
Te0[80]=0xa65353f5; Te0[81]=0xb9d1d168; Te0[82]=0x00000000; Te0[83]=0xc1eded2c;
Te0[84]=0x40202060; Te0[85]=0xe3fcfc1f; Te0[86]=0x79b1b1c8; Te0[87]=0xb65b5bed;
Te0[88]=0xd46a6abe; Te0[89]=0x8dcbcb46; Te0[90]=0x67bebed9; Te0[91]=0x7239394b;
Te0[92]=0x944a4ade; Te0[93]=0x984c4cd4; Te0[94]=0xb05858e8; Te0[95]=0x85cfcf4a;
Te0[96]=0xbbd0d06b; Te0[97]=0xc5efef2a; Te0[98]=0x4faaaae5; Te0[99]=0xedfbfb16;
Te0[100]=0x864343c5; Te0[101]=0x9a4d4dd7; Te0[102]=0x66333355; Te0[103]=0x11858594;
Te0[104]=0x8a4545cf; Te0[105]=0xe9f9f910; Te0[106]=0x04020206; Te0[107]=0xfe7f7f81;
Te0[108]=0xa05050f0; Te0[109]=0x783c3c44; Te0[110]=0x259f9fba; Te0[111]=0x4ba8a8e3;
Te0[112]=0xa25151f3; Te0[113]=0x5da3a3fe; Te0[114]=0x804040c0; Te0[115]=0x058f8f8a;
Te0[116]=0x3f9292ad; Te0[117]=0x219d9dbc; Te0[118]=0x70383848; Te0[119]=0xf1f5f504;
Te0[120]=0x63bcbcdf; Te0[121]=0x77b6b6c1; Te0[122]=0xafdada75; Te0[123]=0x42212163;
Te0[124]=0x20101030; Te0[125]=0xe5ffff1a; Te0[126]=0xfdf3f30e; Te0[127]=0xbfd2d26d;
Te0[128]=0x81cdcd4c; Te0[129]=0x180c0c14; Te0[130]=0x26131335; Te0[131]=0xc3ecec2f;
Te0[132]=0xbe5f5fe1; Te0[133]=0x359797a2; Te0[134]=0x884444cc; Te0[135]=0x2e171739;
Te0[136]=0x93c4c457; Te0[137]=0x55a7a7f2; Te0[138]=0xfc7e7e82; Te0[139]=0x7a3d3d47;
Te0[140]=0xc86464ac; Te0[141]=0xba5d5de7; Te0[142]=0x3219192b; Te0[143]=0xe6737395;
Te0[144]=0xc06060a0; Te0[145]=0x19818198; Te0[146]=0x9e4f4fd1; Te0[147]=0xa3dcdc7f;
Te0[148]=0x44222266; Te0[149]=0x542a2a7e; Te0[150]=0x3b9090ab; Te0[151]=0x0b888883;
Te0[152]=0x8c4646ca; Te0[153]=0xc7eeee29; Te0[154]=0x6bb8b8d3; Te0[155]=0x2814143c;
Te0[156]=0xa7dede79; Te0[157]=0xbc5e5ee2; Te0[158]=0x160b0b1d; Te0[159]=0xaddbdb76;
Te0[160]=0xdbe0e03b; Te0[161]=0x64323256; Te0[162]=0x743a3a4e; Te0[163]=0x140a0a1e;
Te0[164]=0x924949db; Te0[165]=0x0c06060a; Te0[166]=0x4824246c; Te0[167]=0xb85c5ce4;
Te0[168]=0x9fc2c25d; Te0[169]=0xbdd3d36e; Te0[170]=0x43acacef; Te0[171]=0xc46262a6;
Te0[172]=0x399191a8; Te0[173]=0x319595a4; Te0[174]=0xd3e4e437; Te0[175]=0xf279798b;
Te0[176]=0xd5e7e732; Te0[177]=0x8bc8c843; Te0[178]=0x6e373759; Te0[179]=0xda6d6db7;
Te0[180]=0x018d8d8c; Te0[181]=0xb1d5d564; Te0[182]=0x9c4e4ed2; Te0[183]=0x49a9a9e0;
Te0[184]=0xd86c6cb4; Te0[185]=0xac5656fa; Te0[186]=0xf3f4f407; Te0[187]=0xcfeaea25;
Te0[188]=0xca6565af; Te0[189]=0xf47a7a8e; Te0[190]=0x47aeaee9; Te0[191]=0x10080818;
Te0[192]=0x6fbabad5; Te0[193]=0xf0787888; Te0[194]=0x4a25256f; Te0[195]=0x5c2e2e72;
Te0[196]=0x381c1c24; Te0[197]=0x57a6a6f1; Te0[198]=0x73b4b4c7; Te0[199]=0x97c6c651;
Te0[200]=0xcbe8e823; Te0[201]=0xa1dddd7c; Te0[202]=0xe874749c; Te0[203]=0x3e1f1f21;
Te0[204]=0x964b4bdd; Te0[205]=0x61bdbddc; Te0[206]=0x0d8b8b86; Te0[207]=0x0f8a8a85;
Te0[208]=0xe0707090; Te0[209]=0x7c3e3e42; Te0[210]=0x71b5b5c4; Te0[211]=0xcc6666aa;
Te0[212]=0x904848d8; Te0[213]=0x06030305; Te0[214]=0xf7f6f601; Te0[215]=0x1c0e0e12;
Te0[216]=0xc26161a3; Te0[217]=0x6a35355f; Te0[218]=0xae5757f9; Te0[219]=0x69b9b9d0;
Te0[220]=0x17868691; Te0[221]=0x99c1c158; Te0[222]=0x3a1d1d27; Te0[223]=0x279e9eb9;
Te0[224]=0xd9e1e138; Te0[225]=0xebf8f813; Te0[226]=0x2b9898b3; Te0[227]=0x22111133;
Te0[228]=0xd26969bb; Te0[229]=0xa9d9d970; Te0[230]=0x078e8e89; Te0[231]=0x339494a7;
Te0[232]=0x2d9b9bb6; Te0[233]=0x3c1e1e22; Te0[234]=0x15878792; Te0[235]=0xc9e9e920;
Te0[236]=0x87cece49; Te0[237]=0xaa5555ff; Te0[238]=0x50282878; Te0[239]=0xa5dfdf7a;
Te0[240]=0x038c8c8f; Te0[241]=0x59a1a1f8; Te0[242]=0x09898980; Te0[243]=0x1a0d0d17;
Te0[244]=0x65bfbfda; Te0[245]=0xd7e6e631; Te0[246]=0x844242c6; Te0[247]=0xd06868b8;
Te0[248]=0x824141c3; Te0[249]=0x299999b0; Te0[250]=0x5a2d2d77; Te0[251]=0x1e0f0f11;
Te0[252]=0x7bb0b0cb; Te0[253]=0xa85454fc; Te0[254]=0x6dbbbbd6; Te0[255]=0x2c16163a;

// Load the Te1 lookup table
Te1[0]=0xa5c66363; Te1[1]=0x84f87c7c; Te1[2]=0x99ee7777; Te1[3]=0x8df67b7b;
Te1[4]=0x0dfff2f2; Te1[5]=0xbdd66b6b; Te1[6]=0xb1de6f6f; Te1[7]=0x5491c5c5;
Te1[8]=0x50603030; Te1[9]=0x03020101; Te1[10]=0xa9ce6767; Te1[11]=0x7d562b2b;
Te1[12]=0x19e7fefe; Te1[13]=0x62b5d7d7; Te1[14]=0xe64dabab; Te1[15]=0x9aec7676;
Te1[16]=0x458fcaca; Te1[17]=0x9d1f8282; Te1[18]=0x4089c9c9; Te1[19]=0x87fa7d7d;
Te1[20]=0x15effafa; Te1[21]=0xebb25959; Te1[22]=0xc98e4747; Te1[23]=0x0bfbf0f0;
Te1[24]=0xec41adad; Te1[25]=0x67b3d4d4; Te1[26]=0xfd5fa2a2; Te1[27]=0xea45afaf;
Te1[28]=0xbf239c9c; Te1[29]=0xf753a4a4; Te1[30]=0x96e47272; Te1[31]=0x5b9bc0c0;
Te1[32]=0xc275b7b7; Te1[33]=0x1ce1fdfd; Te1[34]=0xae3d9393; Te1[35]=0x6a4c2626;
Te1[36]=0x5a6c3636; Te1[37]=0x417e3f3f; Te1[38]=0x02f5f7f7; Te1[39]=0x4f83cccc;
Te1[40]=0x5c683434; Te1[41]=0xf451a5a5; Te1[42]=0x34d1e5e5; Te1[43]=0x08f9f1f1;
Te1[44]=0x93e27171; Te1[45]=0x73abd8d8; Te1[46]=0x53623131; Te1[47]=0x3f2a1515;
Te1[48]=0x0c080404; Te1[49]=0x5295c7c7; Te1[50]=0x65462323; Te1[51]=0x5e9dc3c3;
Te1[52]=0x28301818; Te1[53]=0xa1379696; Te1[54]=0x0f0a0505; Te1[55]=0xb52f9a9a;
Te1[56]=0x090e0707; Te1[57]=0x36241212; Te1[58]=0x9b1b8080; Te1[59]=0x3ddfe2e2;
Te1[60]=0x26cdebeb; Te1[61]=0x694e2727; Te1[62]=0xcd7fb2b2; Te1[63]=0x9fea7575;
Te1[64]=0x1b120909; Te1[65]=0x9e1d8383; Te1[66]=0x74582c2c; Te1[67]=0x2e341a1a;
Te1[68]=0x2d361b1b; Te1[69]=0xb2dc6e6e; Te1[70]=0xeeb45a5a; Te1[71]=0xfb5ba0a0;
Te1[72]=0xf6a45252; Te1[73]=0x4d763b3b; Te1[74]=0x61b7d6d6; Te1[75]=0xce7db3b3;
Te1[76]=0x7b522929; Te1[77]=0x3edde3e3; Te1[78]=0x715e2f2f; Te1[79]=0x97138484;
Te1[80]=0xf5a65353; Te1[81]=0x68b9d1d1; Te1[82]=0x00000000; Te1[83]=0x2cc1eded;
Te1[84]=0x60402020; Te1[85]=0x1fe3fcfc; Te1[86]=0xc879b1b1; Te1[87]=0xedb65b5b;
Te1[88]=0xbed46a6a; Te1[89]=0x468dcbcb; Te1[90]=0xd967bebe; Te1[91]=0x4b723939;
Te1[92]=0xde944a4a; Te1[93]=0xd4984c4c; Te1[94]=0xe8b05858; Te1[95]=0x4a85cfcf;
Te1[96]=0x6bbbd0d0; Te1[97]=0x2ac5efef; Te1[98]=0xe54faaaa; Te1[99]=0x16edfbfb;
Te1[100]=0xc5864343; Te1[101]=0xd79a4d4d; Te1[102]=0x55663333; Te1[103]=0x94118585;
Te1[104]=0xcf8a4545; Te1[105]=0x10e9f9f9; Te1[106]=0x06040202; Te1[107]=0x81fe7f7f;
Te1[108]=0xf0a05050; Te1[109]=0x44783c3c; Te1[110]=0xba259f9f; Te1[111]=0xe34ba8a8;
Te1[112]=0xf3a25151; Te1[113]=0xfe5da3a3; Te1[114]=0xc0804040; Te1[115]=0x8a058f8f;
Te1[116]=0xad3f9292; Te1[117]=0xbc219d9d; Te1[118]=0x48703838; Te1[119]=0x04f1f5f5;
Te1[120]=0xdf63bcbc; Te1[121]=0xc177b6b6; Te1[122]=0x75afdada; Te1[123]=0x63422121;
Te1[124]=0x30201010; Te1[125]=0x1ae5ffff; Te1[126]=0x0efdf3f3; Te1[127]=0x6dbfd2d2;
Te1[128]=0x4c81cdcd; Te1[129]=0x14180c0c; Te1[130]=0x35261313; Te1[131]=0x2fc3ecec;
Te1[132]=0xe1be5f5f; Te1[133]=0xa2359797; Te1[134]=0xcc884444; Te1[135]=0x392e1717;
Te1[136]=0x5793c4c4; Te1[137]=0xf255a7a7; Te1[138]=0x82fc7e7e; Te1[139]=0x477a3d3d;
Te1[140]=0xacc86464; Te1[141]=0xe7ba5d5d; Te1[142]=0x2b321919; Te1[143]=0x95e67373;
Te1[144]=0xa0c06060; Te1[145]=0x98198181; Te1[146]=0xd19e4f4f; Te1[147]=0x7fa3dcdc;
Te1[148]=0x66442222; Te1[149]=0x7e542a2a; Te1[150]=0xab3b9090; Te1[151]=0x830b8888;
Te1[152]=0xca8c4646; Te1[153]=0x29c7eeee; Te1[154]=0xd36bb8b8; Te1[155]=0x3c281414;
Te1[156]=0x79a7dede; Te1[157]=0xe2bc5e5e; Te1[158]=0x1d160b0b; Te1[159]=0x76addbdb;
Te1[160]=0x3bdbe0e0; Te1[161]=0x56643232; Te1[162]=0x4e743a3a; Te1[163]=0x1e140a0a;
Te1[164]=0xdb924949; Te1[165]=0x0a0c0606; Te1[166]=0x6c482424; Te1[167]=0xe4b85c5c;
Te1[168]=0x5d9fc2c2; Te1[169]=0x6ebdd3d3; Te1[170]=0xef43acac; Te1[171]=0xa6c46262;
Te1[172]=0xa8399191; Te1[173]=0xa4319595; Te1[174]=0x37d3e4e4; Te1[175]=0x8bf27979;
Te1[176]=0x32d5e7e7; Te1[177]=0x438bc8c8; Te1[178]=0x596e3737; Te1[179]=0xb7da6d6d;
Te1[180]=0x8c018d8d; Te1[181]=0x64b1d5d5; Te1[182]=0xd29c4e4e; Te1[183]=0xe049a9a9;
Te1[184]=0xb4d86c6c; Te1[185]=0xfaac5656; Te1[186]=0x07f3f4f4; Te1[187]=0x25cfeaea;
Te1[188]=0xafca6565; Te1[189]=0x8ef47a7a; Te1[190]=0xe947aeae; Te1[191]=0x18100808;
Te1[192]=0xd56fbaba; Te1[193]=0x88f07878; Te1[194]=0x6f4a2525; Te1[195]=0x725c2e2e;
Te1[196]=0x24381c1c; Te1[197]=0xf157a6a6; Te1[198]=0xc773b4b4; Te1[199]=0x5197c6c6;
Te1[200]=0x23cbe8e8; Te1[201]=0x7ca1dddd; Te1[202]=0x9ce87474; Te1[203]=0x213e1f1f;
Te1[204]=0xdd964b4b; Te1[205]=0xdc61bdbd; Te1[206]=0x860d8b8b; Te1[207]=0x850f8a8a;
Te1[208]=0x90e07070; Te1[209]=0x427c3e3e; Te1[210]=0xc471b5b5; Te1[211]=0xaacc6666;
Te1[212]=0xd8904848; Te1[213]=0x05060303; Te1[214]=0x01f7f6f6; Te1[215]=0x121c0e0e;
Te1[216]=0xa3c26161; Te1[217]=0x5f6a3535; Te1[218]=0xf9ae5757; Te1[219]=0xd069b9b9;
Te1[220]=0x91178686; Te1[221]=0x5899c1c1; Te1[222]=0x273a1d1d; Te1[223]=0xb9279e9e;
Te1[224]=0x38d9e1e1; Te1[225]=0x13ebf8f8; Te1[226]=0xb32b9898; Te1[227]=0x33221111;
Te1[228]=0xbbd26969; Te1[229]=0x70a9d9d9; Te1[230]=0x89078e8e; Te1[231]=0xa7339494;
Te1[232]=0xb62d9b9b; Te1[233]=0x223c1e1e; Te1[234]=0x92158787; Te1[235]=0x20c9e9e9;
Te1[236]=0x4987cece; Te1[237]=0xffaa5555; Te1[238]=0x78502828; Te1[239]=0x7aa5dfdf;
Te1[240]=0x8f038c8c; Te1[241]=0xf859a1a1; Te1[242]=0x80098989; Te1[243]=0x171a0d0d;
Te1[244]=0xda65bfbf; Te1[245]=0x31d7e6e6; Te1[246]=0xc6844242; Te1[247]=0xb8d06868;
Te1[248]=0xc3824141; Te1[249]=0xb0299999; Te1[250]=0x775a2d2d; Te1[251]=0x111e0f0f;
Te1[252]=0xcb7bb0b0; Te1[253]=0xfca85454; Te1[254]=0xd66dbbbb; Te1[255]=0x3a2c1616;

// Load the Te2 lookup table
Te2[0]=0x63a5c663; Te2[1]=0x7c84f87c; Te2[2]=0x7799ee77; Te2[3]=0x7b8df67b;
Te2[4]=0xf20dfff2; Te2[5]=0x6bbdd66b; Te2[6]=0x6fb1de6f; Te2[7]=0xc55491c5;
Te2[8]=0x30506030; Te2[9]=0x01030201; Te2[10]=0x67a9ce67; Te2[11]=0x2b7d562b;
Te2[12]=0xfe19e7fe; Te2[13]=0xd762b5d7; Te2[14]=0xabe64dab; Te2[15]=0x769aec76;
Te2[16]=0xca458fca; Te2[17]=0x829d1f82; Te2[18]=0xc94089c9; Te2[19]=0x7d87fa7d;
Te2[20]=0xfa15effa; Te2[21]=0x59ebb259; Te2[22]=0x47c98e47; Te2[23]=0xf00bfbf0;
Te2[24]=0xadec41ad; Te2[25]=0xd467b3d4; Te2[26]=0xa2fd5fa2; Te2[27]=0xafea45af;
Te2[28]=0x9cbf239c; Te2[29]=0xa4f753a4; Te2[30]=0x7296e472; Te2[31]=0xc05b9bc0;
Te2[32]=0xb7c275b7; Te2[33]=0xfd1ce1fd; Te2[34]=0x93ae3d93; Te2[35]=0x266a4c26;
Te2[36]=0x365a6c36; Te2[37]=0x3f417e3f; Te2[38]=0xf702f5f7; Te2[39]=0xcc4f83cc;
Te2[40]=0x345c6834; Te2[41]=0xa5f451a5; Te2[42]=0xe534d1e5; Te2[43]=0xf108f9f1;
Te2[44]=0x7193e271; Te2[45]=0xd873abd8; Te2[46]=0x31536231; Te2[47]=0x153f2a15;
Te2[48]=0x040c0804; Te2[49]=0xc75295c7; Te2[50]=0x23654623; Te2[51]=0xc35e9dc3;
Te2[52]=0x18283018; Te2[53]=0x96a13796; Te2[54]=0x050f0a05; Te2[55]=0x9ab52f9a;
Te2[56]=0x07090e07; Te2[57]=0x12362412; Te2[58]=0x809b1b80; Te2[59]=0xe23ddfe2;
Te2[60]=0xeb26cdeb; Te2[61]=0x27694e27; Te2[62]=0xb2cd7fb2; Te2[63]=0x759fea75;
Te2[64]=0x091b1209; Te2[65]=0x839e1d83; Te2[66]=0x2c74582c; Te2[67]=0x1a2e341a;
Te2[68]=0x1b2d361b; Te2[69]=0x6eb2dc6e; Te2[70]=0x5aeeb45a; Te2[71]=0xa0fb5ba0;
Te2[72]=0x52f6a452; Te2[73]=0x3b4d763b; Te2[74]=0xd661b7d6; Te2[75]=0xb3ce7db3;
Te2[76]=0x297b5229; Te2[77]=0xe33edde3; Te2[78]=0x2f715e2f; Te2[79]=0x84971384;
Te2[80]=0x53f5a653; Te2[81]=0xd168b9d1; Te2[82]=0x00000000; Te2[83]=0xed2cc1ed;
Te2[84]=0x20604020; Te2[85]=0xfc1fe3fc; Te2[86]=0xb1c879b1; Te2[87]=0x5bedb65b;
Te2[88]=0x6abed46a; Te2[89]=0xcb468dcb; Te2[90]=0xbed967be; Te2[91]=0x394b7239;
Te2[92]=0x4ade944a; Te2[93]=0x4cd4984c; Te2[94]=0x58e8b058; Te2[95]=0xcf4a85cf;
Te2[96]=0xd06bbbd0; Te2[97]=0xef2ac5ef; Te2[98]=0xaae54faa; Te2[99]=0xfb16edfb;
Te2[100]=0x43c58643; Te2[101]=0x4dd79a4d; Te2[102]=0x33556633; Te2[103]=0x85941185;
Te2[104]=0x45cf8a45; Te2[105]=0xf910e9f9; Te2[106]=0x02060402; Te2[107]=0x7f81fe7f;
Te2[108]=0x50f0a050; Te2[109]=0x3c44783c; Te2[110]=0x9fba259f; Te2[111]=0xa8e34ba8;
Te2[112]=0x51f3a251; Te2[113]=0xa3fe5da3; Te2[114]=0x40c08040; Te2[115]=0x8f8a058f;
Te2[116]=0x92ad3f92; Te2[117]=0x9dbc219d; Te2[118]=0x38487038; Te2[119]=0xf504f1f5;
Te2[120]=0xbcdf63bc; Te2[121]=0xb6c177b6; Te2[122]=0xda75afda; Te2[123]=0x21634221;
Te2[124]=0x10302010; Te2[125]=0xff1ae5ff; Te2[126]=0xf30efdf3; Te2[127]=0xd26dbfd2;
Te2[128]=0xcd4c81cd; Te2[129]=0x0c14180c; Te2[130]=0x13352613; Te2[131]=0xec2fc3ec;
Te2[132]=0x5fe1be5f; Te2[133]=0x97a23597; Te2[134]=0x44cc8844; Te2[135]=0x17392e17;
Te2[136]=0xc45793c4; Te2[137]=0xa7f255a7; Te2[138]=0x7e82fc7e; Te2[139]=0x3d477a3d;
Te2[140]=0x64acc864; Te2[141]=0x5de7ba5d; Te2[142]=0x192b3219; Te2[143]=0x7395e673;
Te2[144]=0x60a0c060; Te2[145]=0x81981981; Te2[146]=0x4fd19e4f; Te2[147]=0xdc7fa3dc;
Te2[148]=0x22664422; Te2[149]=0x2a7e542a; Te2[150]=0x90ab3b90; Te2[151]=0x88830b88;
Te2[152]=0x46ca8c46; Te2[153]=0xee29c7ee; Te2[154]=0xb8d36bb8; Te2[155]=0x143c2814;
Te2[156]=0xde79a7de; Te2[157]=0x5ee2bc5e; Te2[158]=0x0b1d160b; Te2[159]=0xdb76addb;
Te2[160]=0xe03bdbe0; Te2[161]=0x32566432; Te2[162]=0x3a4e743a; Te2[163]=0x0a1e140a;
Te2[164]=0x49db9249; Te2[165]=0x060a0c06; Te2[166]=0x246c4824; Te2[167]=0x5ce4b85c;
Te2[168]=0xc25d9fc2; Te2[169]=0xd36ebdd3; Te2[170]=0xacef43ac; Te2[171]=0x62a6c462;
Te2[172]=0x91a83991; Te2[173]=0x95a43195; Te2[174]=0xe437d3e4; Te2[175]=0x798bf279;
Te2[176]=0xe732d5e7; Te2[177]=0xc8438bc8; Te2[178]=0x37596e37; Te2[179]=0x6db7da6d;
Te2[180]=0x8d8c018d; Te2[181]=0xd564b1d5; Te2[182]=0x4ed29c4e; Te2[183]=0xa9e049a9;
Te2[184]=0x6cb4d86c; Te2[185]=0x56faac56; Te2[186]=0xf407f3f4; Te2[187]=0xea25cfea;
Te2[188]=0x65afca65; Te2[189]=0x7a8ef47a; Te2[190]=0xaee947ae; Te2[191]=0x08181008;
Te2[192]=0xbad56fba; Te2[193]=0x7888f078; Te2[194]=0x256f4a25; Te2[195]=0x2e725c2e;
Te2[196]=0x1c24381c; Te2[197]=0xa6f157a6; Te2[198]=0xb4c773b4; Te2[199]=0xc65197c6;
Te2[200]=0xe823cbe8; Te2[201]=0xdd7ca1dd; Te2[202]=0x749ce874; Te2[203]=0x1f213e1f;
Te2[204]=0x4bdd964b; Te2[205]=0xbddc61bd; Te2[206]=0x8b860d8b; Te2[207]=0x8a850f8a;
Te2[208]=0x7090e070; Te2[209]=0x3e427c3e; Te2[210]=0xb5c471b5; Te2[211]=0x66aacc66;
Te2[212]=0x48d89048; Te2[213]=0x03050603; Te2[214]=0xf601f7f6; Te2[215]=0x0e121c0e;
Te2[216]=0x61a3c261; Te2[217]=0x355f6a35; Te2[218]=0x57f9ae57; Te2[219]=0xb9d069b9;
Te2[220]=0x86911786; Te2[221]=0xc15899c1; Te2[222]=0x1d273a1d; Te2[223]=0x9eb9279e;
Te2[224]=0xe138d9e1; Te2[225]=0xf813ebf8; Te2[226]=0x98b32b98; Te2[227]=0x11332211;
Te2[228]=0x69bbd269; Te2[229]=0xd970a9d9; Te2[230]=0x8e89078e; Te2[231]=0x94a73394;
Te2[232]=0x9bb62d9b; Te2[233]=0x1e223c1e; Te2[234]=0x87921587; Te2[235]=0xe920c9e9;
Te2[236]=0xce4987ce; Te2[237]=0x55ffaa55; Te2[238]=0x28785028; Te2[239]=0xdf7aa5df;
Te2[240]=0x8c8f038c; Te2[241]=0xa1f859a1; Te2[242]=0x89800989; Te2[243]=0x0d171a0d;
Te2[244]=0xbfda65bf; Te2[245]=0xe631d7e6; Te2[246]=0x42c68442; Te2[247]=0x68b8d068;
Te2[248]=0x41c38241; Te2[249]=0x99b02999; Te2[250]=0x2d775a2d; Te2[251]=0x0f111e0f;
Te2[252]=0xb0cb7bb0; Te2[253]=0x54fca854; Te2[254]=0xbbd66dbb; Te2[255]=0x163a2c16;

// Load the Te3 lookup table
Te3[0]=0x6363a5c6; Te3[1]=0x7c7c84f8; Te3[2]=0x777799ee; Te3[3]=0x7b7b8df6;
Te3[4]=0xf2f20dff; Te3[5]=0x6b6bbdd6; Te3[6]=0x6f6fb1de; Te3[7]=0xc5c55491;
Te3[8]=0x30305060; Te3[9]=0x01010302; Te3[10]=0x6767a9ce; Te3[11]=0x2b2b7d56;
Te3[12]=0xfefe19e7; Te3[13]=0xd7d762b5; Te3[14]=0xababe64d; Te3[15]=0x76769aec;
Te3[16]=0xcaca458f; Te3[17]=0x82829d1f; Te3[18]=0xc9c94089; Te3[19]=0x7d7d87fa;
Te3[20]=0xfafa15ef; Te3[21]=0x5959ebb2; Te3[22]=0x4747c98e; Te3[23]=0xf0f00bfb;
Te3[24]=0xadadec41; Te3[25]=0xd4d467b3; Te3[26]=0xa2a2fd5f; Te3[27]=0xafafea45;
Te3[28]=0x9c9cbf23; Te3[29]=0xa4a4f753; Te3[30]=0x727296e4; Te3[31]=0xc0c05b9b;
Te3[32]=0xb7b7c275; Te3[33]=0xfdfd1ce1; Te3[34]=0x9393ae3d; Te3[35]=0x26266a4c;
Te3[36]=0x36365a6c; Te3[37]=0x3f3f417e; Te3[38]=0xf7f702f5; Te3[39]=0xcccc4f83;
Te3[40]=0x34345c68; Te3[41]=0xa5a5f451; Te3[42]=0xe5e534d1; Te3[43]=0xf1f108f9;
Te3[44]=0x717193e2; Te3[45]=0xd8d873ab; Te3[46]=0x31315362; Te3[47]=0x15153f2a;
Te3[48]=0x04040c08; Te3[49]=0xc7c75295; Te3[50]=0x23236546; Te3[51]=0xc3c35e9d;
Te3[52]=0x18182830; Te3[53]=0x9696a137; Te3[54]=0x05050f0a; Te3[55]=0x9a9ab52f;
Te3[56]=0x0707090e; Te3[57]=0x12123624; Te3[58]=0x80809b1b; Te3[59]=0xe2e23ddf;
Te3[60]=0xebeb26cd; Te3[61]=0x2727694e; Te3[62]=0xb2b2cd7f; Te3[63]=0x75759fea;
Te3[64]=0x09091b12; Te3[65]=0x83839e1d; Te3[66]=0x2c2c7458; Te3[67]=0x1a1a2e34;
Te3[68]=0x1b1b2d36; Te3[69]=0x6e6eb2dc; Te3[70]=0x5a5aeeb4; Te3[71]=0xa0a0fb5b;
Te3[72]=0x5252f6a4; Te3[73]=0x3b3b4d76; Te3[74]=0xd6d661b7; Te3[75]=0xb3b3ce7d;
Te3[76]=0x29297b52; Te3[77]=0xe3e33edd; Te3[78]=0x2f2f715e; Te3[79]=0x84849713;
Te3[80]=0x5353f5a6; Te3[81]=0xd1d168b9; Te3[82]=0x00000000; Te3[83]=0xeded2cc1;
Te3[84]=0x20206040; Te3[85]=0xfcfc1fe3; Te3[86]=0xb1b1c879; Te3[87]=0x5b5bedb6;
Te3[88]=0x6a6abed4; Te3[89]=0xcbcb468d; Te3[90]=0xbebed967; Te3[91]=0x39394b72;
Te3[92]=0x4a4ade94; Te3[93]=0x4c4cd498; Te3[94]=0x5858e8b0; Te3[95]=0xcfcf4a85;
Te3[96]=0xd0d06bbb; Te3[97]=0xefef2ac5; Te3[98]=0xaaaae54f; Te3[99]=0xfbfb16ed;
Te3[100]=0x4343c586; Te3[101]=0x4d4dd79a; Te3[102]=0x33335566; Te3[103]=0x85859411;
Te3[104]=0x4545cf8a; Te3[105]=0xf9f910e9; Te3[106]=0x02020604; Te3[107]=0x7f7f81fe;
Te3[108]=0x5050f0a0; Te3[109]=0x3c3c4478; Te3[110]=0x9f9fba25; Te3[111]=0xa8a8e34b;
Te3[112]=0x5151f3a2; Te3[113]=0xa3a3fe5d; Te3[114]=0x4040c080; Te3[115]=0x8f8f8a05;
Te3[116]=0x9292ad3f; Te3[117]=0x9d9dbc21; Te3[118]=0x38384870; Te3[119]=0xf5f504f1;
Te3[120]=0xbcbcdf63; Te3[121]=0xb6b6c177; Te3[122]=0xdada75af; Te3[123]=0x21216342;
Te3[124]=0x10103020; Te3[125]=0xffff1ae5; Te3[126]=0xf3f30efd; Te3[127]=0xd2d26dbf;
Te3[128]=0xcdcd4c81; Te3[129]=0x0c0c1418; Te3[130]=0x13133526; Te3[131]=0xecec2fc3;
Te3[132]=0x5f5fe1be; Te3[133]=0x9797a235; Te3[134]=0x4444cc88; Te3[135]=0x1717392e;
Te3[136]=0xc4c45793; Te3[137]=0xa7a7f255; Te3[138]=0x7e7e82fc; Te3[139]=0x3d3d477a;
Te3[140]=0x6464acc8; Te3[141]=0x5d5de7ba; Te3[142]=0x19192b32; Te3[143]=0x737395e6;
Te3[144]=0x6060a0c0; Te3[145]=0x81819819; Te3[146]=0x4f4fd19e; Te3[147]=0xdcdc7fa3;
Te3[148]=0x22226644; Te3[149]=0x2a2a7e54; Te3[150]=0x9090ab3b; Te3[151]=0x8888830b;
Te3[152]=0x4646ca8c; Te3[153]=0xeeee29c7; Te3[154]=0xb8b8d36b; Te3[155]=0x14143c28;
Te3[156]=0xdede79a7; Te3[157]=0x5e5ee2bc; Te3[158]=0x0b0b1d16; Te3[159]=0xdbdb76ad;
Te3[160]=0xe0e03bdb; Te3[161]=0x32325664; Te3[162]=0x3a3a4e74; Te3[163]=0x0a0a1e14;
Te3[164]=0x4949db92; Te3[165]=0x06060a0c; Te3[166]=0x24246c48; Te3[167]=0x5c5ce4b8;
Te3[168]=0xc2c25d9f; Te3[169]=0xd3d36ebd; Te3[170]=0xacacef43; Te3[171]=0x6262a6c4;
Te3[172]=0x9191a839; Te3[173]=0x9595a431; Te3[174]=0xe4e437d3; Te3[175]=0x79798bf2;
Te3[176]=0xe7e732d5; Te3[177]=0xc8c8438b; Te3[178]=0x3737596e; Te3[179]=0x6d6db7da;
Te3[180]=0x8d8d8c01; Te3[181]=0xd5d564b1; Te3[182]=0x4e4ed29c; Te3[183]=0xa9a9e049;
Te3[184]=0x6c6cb4d8; Te3[185]=0x5656faac; Te3[186]=0xf4f407f3; Te3[187]=0xeaea25cf;
Te3[188]=0x6565afca; Te3[189]=0x7a7a8ef4; Te3[190]=0xaeaee947; Te3[191]=0x08081810;
Te3[192]=0xbabad56f; Te3[193]=0x787888f0; Te3[194]=0x25256f4a; Te3[195]=0x2e2e725c;
Te3[196]=0x1c1c2438; Te3[197]=0xa6a6f157; Te3[198]=0xb4b4c773; Te3[199]=0xc6c65197;
Te3[200]=0xe8e823cb; Te3[201]=0xdddd7ca1; Te3[202]=0x74749ce8; Te3[203]=0x1f1f213e;
Te3[204]=0x4b4bdd96; Te3[205]=0xbdbddc61; Te3[206]=0x8b8b860d; Te3[207]=0x8a8a850f;
Te3[208]=0x707090e0; Te3[209]=0x3e3e427c; Te3[210]=0xb5b5c471; Te3[211]=0x6666aacc;
Te3[212]=0x4848d890; Te3[213]=0x03030506; Te3[214]=0xf6f601f7; Te3[215]=0x0e0e121c;
Te3[216]=0x6161a3c2; Te3[217]=0x35355f6a; Te3[218]=0x5757f9ae; Te3[219]=0xb9b9d069;
Te3[220]=0x86869117; Te3[221]=0xc1c15899; Te3[222]=0x1d1d273a; Te3[223]=0x9e9eb927;
Te3[224]=0xe1e138d9; Te3[225]=0xf8f813eb; Te3[226]=0x9898b32b; Te3[227]=0x11113322;
Te3[228]=0x6969bbd2; Te3[229]=0xd9d970a9; Te3[230]=0x8e8e8907; Te3[231]=0x9494a733;
Te3[232]=0x9b9bb62d; Te3[233]=0x1e1e223c; Te3[234]=0x87879215; Te3[235]=0xe9e920c9;
Te3[236]=0xcece4987; Te3[237]=0x5555ffaa; Te3[238]=0x28287850; Te3[239]=0xdfdf7aa5;
Te3[240]=0x8c8c8f03; Te3[241]=0xa1a1f859; Te3[242]=0x89898009; Te3[243]=0x0d0d171a;
Te3[244]=0xbfbfda65; Te3[245]=0xe6e631d7; Te3[246]=0x4242c684; Te3[247]=0x6868b8d0;
Te3[248]=0x4141c382; Te3[249]=0x9999b029; Te3[250]=0x2d2d775a; Te3[251]=0x0f0f111e;
Te3[252]=0xb0b0cb7b; Te3[253]=0x5454fca8; Te3[254]=0xbbbbd66d; Te3[255]=0x16163a2c;

// Load the Te4 lookup table
Te4[0]=0x63636363; Te4[1]=0x7c7c7c7c; Te4[2]=0x77777777; Te4[3]=0x7b7b7b7b;
Te4[4]=0xf2f2f2f2; Te4[5]=0x6b6b6b6b; Te4[6]=0x6f6f6f6f; Te4[7]=0xc5c5c5c5;
Te4[8]=0x30303030; Te4[9]=0x01010101; Te4[10]=0x67676767; Te4[11]=0x2b2b2b2b;
Te4[12]=0xfefefefe; Te4[13]=0xd7d7d7d7; Te4[14]=0xabababab; Te4[15]=0x76767676;
Te4[16]=0xcacacaca; Te4[17]=0x82828282; Te4[18]=0xc9c9c9c9; Te4[19]=0x7d7d7d7d;
Te4[20]=0xfafafafa; Te4[21]=0x59595959; Te4[22]=0x47474747; Te4[23]=0xf0f0f0f0;
Te4[24]=0xadadadad; Te4[25]=0xd4d4d4d4; Te4[26]=0xa2a2a2a2; Te4[27]=0xafafafaf;
Te4[28]=0x9c9c9c9c; Te4[29]=0xa4a4a4a4; Te4[30]=0x72727272; Te4[31]=0xc0c0c0c0;
Te4[32]=0xb7b7b7b7; Te4[33]=0xfdfdfdfd; Te4[34]=0x93939393; Te4[35]=0x26262626;
Te4[36]=0x36363636; Te4[37]=0x3f3f3f3f; Te4[38]=0xf7f7f7f7; Te4[39]=0xcccccccc;
Te4[40]=0x34343434; Te4[41]=0xa5a5a5a5; Te4[42]=0xe5e5e5e5; Te4[43]=0xf1f1f1f1;
Te4[44]=0x71717171; Te4[45]=0xd8d8d8d8; Te4[46]=0x31313131; Te4[47]=0x15151515;
Te4[48]=0x04040404; Te4[49]=0xc7c7c7c7; Te4[50]=0x23232323; Te4[51]=0xc3c3c3c3;
Te4[52]=0x18181818; Te4[53]=0x96969696; Te4[54]=0x05050505; Te4[55]=0x9a9a9a9a;
Te4[56]=0x07070707; Te4[57]=0x12121212; Te4[58]=0x80808080; Te4[59]=0xe2e2e2e2;
Te4[60]=0xebebebeb; Te4[61]=0x27272727; Te4[62]=0xb2b2b2b2; Te4[63]=0x75757575;
Te4[64]=0x09090909; Te4[65]=0x83838383; Te4[66]=0x2c2c2c2c; Te4[67]=0x1a1a1a1a;
Te4[68]=0x1b1b1b1b; Te4[69]=0x6e6e6e6e; Te4[70]=0x5a5a5a5a; Te4[71]=0xa0a0a0a0;
Te4[72]=0x52525252; Te4[73]=0x3b3b3b3b; Te4[74]=0xd6d6d6d6; Te4[75]=0xb3b3b3b3;
Te4[76]=0x29292929; Te4[77]=0xe3e3e3e3; Te4[78]=0x2f2f2f2f; Te4[79]=0x84848484;
Te4[80]=0x53535353; Te4[81]=0xd1d1d1d1; Te4[82]=0x00000000; Te4[83]=0xedededed;
Te4[84]=0x20202020; Te4[85]=0xfcfcfcfc; Te4[86]=0xb1b1b1b1; Te4[87]=0x5b5b5b5b;
Te4[88]=0x6a6a6a6a; Te4[89]=0xcbcbcbcb; Te4[90]=0xbebebebe; Te4[91]=0x39393939;
Te4[92]=0x4a4a4a4a; Te4[93]=0x4c4c4c4c; Te4[94]=0x58585858; Te4[95]=0xcfcfcfcf;
Te4[96]=0xd0d0d0d0; Te4[97]=0xefefefef; Te4[98]=0xaaaaaaaa; Te4[99]=0xfbfbfbfb;
Te4[100]=0x43434343; Te4[101]=0x4d4d4d4d; Te4[102]=0x33333333; Te4[103]=0x85858585;
Te4[104]=0x45454545; Te4[105]=0xf9f9f9f9; Te4[106]=0x02020202; Te4[107]=0x7f7f7f7f;
Te4[108]=0x50505050; Te4[109]=0x3c3c3c3c; Te4[110]=0x9f9f9f9f; Te4[111]=0xa8a8a8a8;
Te4[112]=0x51515151; Te4[113]=0xa3a3a3a3; Te4[114]=0x40404040; Te4[115]=0x8f8f8f8f;
Te4[116]=0x92929292; Te4[117]=0x9d9d9d9d; Te4[118]=0x38383838; Te4[119]=0xf5f5f5f5;
Te4[120]=0xbcbcbcbc; Te4[121]=0xb6b6b6b6; Te4[122]=0xdadadada; Te4[123]=0x21212121;
Te4[124]=0x10101010; Te4[125]=0xffffffff; Te4[126]=0xf3f3f3f3; Te4[127]=0xd2d2d2d2;
Te4[128]=0xcdcdcdcd; Te4[129]=0x0c0c0c0c; Te4[130]=0x13131313; Te4[131]=0xecececec;
Te4[132]=0x5f5f5f5f; Te4[133]=0x97979797; Te4[134]=0x44444444; Te4[135]=0x17171717;
Te4[136]=0xc4c4c4c4; Te4[137]=0xa7a7a7a7; Te4[138]=0x7e7e7e7e; Te4[139]=0x3d3d3d3d;
Te4[140]=0x64646464; Te4[141]=0x5d5d5d5d; Te4[142]=0x19191919; Te4[143]=0x73737373;
Te4[144]=0x60606060; Te4[145]=0x81818181; Te4[146]=0x4f4f4f4f; Te4[147]=0xdcdcdcdc;
Te4[148]=0x22222222; Te4[149]=0x2a2a2a2a; Te4[150]=0x90909090; Te4[151]=0x88888888;
Te4[152]=0x46464646; Te4[153]=0xeeeeeeee; Te4[154]=0xb8b8b8b8; Te4[155]=0x14141414;
Te4[156]=0xdededede; Te4[157]=0x5e5e5e5e; Te4[158]=0x0b0b0b0b; Te4[159]=0xdbdbdbdb;
Te4[160]=0xe0e0e0e0; Te4[161]=0x32323232; Te4[162]=0x3a3a3a3a; Te4[163]=0x0a0a0a0a;
Te4[164]=0x49494949; Te4[165]=0x06060606; Te4[166]=0x24242424; Te4[167]=0x5c5c5c5c;
Te4[168]=0xc2c2c2c2; Te4[169]=0xd3d3d3d3; Te4[170]=0xacacacac; Te4[171]=0x62626262;
Te4[172]=0x91919191; Te4[173]=0x95959595; Te4[174]=0xe4e4e4e4; Te4[175]=0x79797979;
Te4[176]=0xe7e7e7e7; Te4[177]=0xc8c8c8c8; Te4[178]=0x37373737; Te4[179]=0x6d6d6d6d;
Te4[180]=0x8d8d8d8d; Te4[181]=0xd5d5d5d5; Te4[182]=0x4e4e4e4e; Te4[183]=0xa9a9a9a9;
Te4[184]=0x6c6c6c6c; Te4[185]=0x56565656; Te4[186]=0xf4f4f4f4; Te4[187]=0xeaeaeaea;
Te4[188]=0x65656565; Te4[189]=0x7a7a7a7a; Te4[190]=0xaeaeaeae; Te4[191]=0x08080808;
Te4[192]=0xbabababa; Te4[193]=0x78787878; Te4[194]=0x25252525; Te4[195]=0x2e2e2e2e;
Te4[196]=0x1c1c1c1c; Te4[197]=0xa6a6a6a6; Te4[198]=0xb4b4b4b4; Te4[199]=0xc6c6c6c6;
Te4[200]=0xe8e8e8e8; Te4[201]=0xdddddddd; Te4[202]=0x74747474; Te4[203]=0x1f1f1f1f;
Te4[204]=0x4b4b4b4b; Te4[205]=0xbdbdbdbd; Te4[206]=0x8b8b8b8b; Te4[207]=0x8a8a8a8a;
Te4[208]=0x70707070; Te4[209]=0x3e3e3e3e; Te4[210]=0xb5b5b5b5; Te4[211]=0x66666666;
Te4[212]=0x48484848; Te4[213]=0x03030303; Te4[214]=0xf6f6f6f6; Te4[215]=0x0e0e0e0e;
Te4[216]=0x61616161; Te4[217]=0x35353535; Te4[218]=0x57575757; Te4[219]=0xb9b9b9b9;
Te4[220]=0x86868686; Te4[221]=0xc1c1c1c1; Te4[222]=0x1d1d1d1d; Te4[223]=0x9e9e9e9e;
Te4[224]=0xe1e1e1e1; Te4[225]=0xf8f8f8f8; Te4[226]=0x98989898; Te4[227]=0x11111111;
Te4[228]=0x69696969; Te4[229]=0xd9d9d9d9; Te4[230]=0x8e8e8e8e; Te4[231]=0x94949494;
Te4[232]=0x9b9b9b9b; Te4[233]=0x1e1e1e1e; Te4[234]=0x87878787; Te4[235]=0xe9e9e9e9;
Te4[236]=0xcececece; Te4[237]=0x55555555; Te4[238]=0x28282828; Te4[239]=0xdfdfdfdf;
Te4[240]=0x8c8c8c8c; Te4[241]=0xa1a1a1a1; Te4[242]=0x89898989; Te4[243]=0x0d0d0d0d;
Te4[244]=0xbfbfbfbf; Te4[245]=0xe6e6e6e6; Te4[246]=0x42424242; Te4[247]=0x68686868;
Te4[248]=0x41414141; Te4[249]=0x99999999; Te4[250]=0x2d2d2d2d; Te4[251]=0x0f0f0f0f;
Te4[252]=0xb0b0b0b0; Te4[253]=0x54545454; Te4[254]=0xbbbbbbbb; Te4[255]=0x16161616;

// Load the rcon lookup table
rcon[0]=0x01000000; rcon[1]=0x02000000; rcon[2]=0x04000000; rcon[3]=0x08000000;
rcon[4]=0x10000000; rcon[5]=0x20000000; rcon[6]=0x40000000; rcon[7]=0x80000000;
rcon[8]=0x1B000000; rcon[9]=0x36000000;
		}

		/**
		 * Convert 4 bytes to a 32-bit word.
		 * @param {int} bv Byte-pointer to 4 bytes for conversion.
		 * @returns {int} 32-bit word.
		 */
		function btow(bv) {
			return (
				(bv[0] << 24) ^
				(bv[1] << 16) ^
				(bv[2] <<  8) ^
				(bv[3]      )
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
			var rkView8 = new stdlib.Uint8Array(heap, rk, 240);
			var rkView = new stdlib.Uint32Array(heap, rk, 60);
			var keyView = new stdlib.Uint32Array(heap, key, 8);
//			var keyView8 = new stdlib.Uint8Array(heap, key, 32);
			var p, genLen, i = 0;
			var temp = 0;
			bitLength = 256;

			// Copy the first 8 words
			for(p = 0, genLen = 0 ; p < 8 ; p++, genLen++) {
				rkView[p] = keyView[p];
			}

			while(genLen < 60) {
				// Save previous word
				temp = rkView[genLen-1];

				// Apply Schedule Core (rotate, s-box lookup, xor rcon)
				temp = (
					( Te4[(temp >>>  0) & 0xff] & 0xff000000) ^
					( Te4[(temp >>> 24)       ] & 0x00ff0000) ^
					( Te4[(temp >>> 16) & 0xff] & 0x0000ff00) ^
					((Te4[(temp >>>  8) & 0xff] & 0x000000ff) ^ stdlib.Math.pow(2, (i++)))
				);

				// Store new word
				rkView[genLen] = temp ^ rkView[genLen - 8];
				genLen++;

				// Store next 3 words
				for(p = 0 ; p < 3 ; p++, genLen++) {
					rkView[genLen] = rkView[genLen - 8] ^ rkView[genLen - 1];
				}

				if(bitLength == 256) {
					// Save previous word
					temp = rkView[genLen-1];

					// Apply S-box
					temp = (
						(Te4[(temp >>> 24)       ] & 0xff000000) ^
						(Te4[(temp >>> 16) & 0xff] & 0x00ff0000) ^
						(Te4[(temp >>>  8) & 0xff] & 0x0000ff00) ^
						(Te4[(temp       ) & 0xff] & 0x000000ff)
					);

					// Store new word
					rkView[genLen] = temp ^ rkView[genLen - 8];
					genLen++;

					// Store next 3 words
					for(p = 0 ; p < 3 ; p++, genLen++) {
						rkView[genLen] = rkView[genLen - 8] ^ rkView[genLen - 1];
					}
				}
			}

			for(var k = 0 ; k < 240 ; k += 16) {
				console.log(Hex.toHex(heap, rkOffset + k, 16));
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
		var plainView = new Uint8Array(heap, plainOffset, 16);

		// set the key
		for(i = 0 ; i < 32 ; i++) {
			keyView[i] = i;
		}

		nRounds = asm.createEncrypt(rkOffset, keyOffset);

		// set plaintext
		for(i = 0 ; i < 16 ; i++) {
			plainView[i] = 16 * i + i;
		}

		asm.encrypt(rkOffset, nRounds, plainOffset, cipherOffset);
		hex = Hex.toHex(heap, cipherOffset, 16);
		console.log("ciphertext = " + hex);
	}

	return {
		"encrypt": encrypt,
		"decrypt": decrypt,
		"asm": asm,
		"testEncrypt": testEncrypt
	}

}();
