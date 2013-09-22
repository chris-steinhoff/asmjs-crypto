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
		var Sbox = 0;
		var InvSbox = 256;
		var Xtime2Sbox = 512;
		var Xtime3Sbox = 768;
		var Xtime9 = 1024;
		var XtimeB = 1280;
		var XtimeD = 1536;
		var XtimeE = 1792;
		var rcon = 2048;
		var temp = 2060; // rcon + 11 + 1
		var state = 2076; // temp + 16

		/**
		 * Initialize lookup tables in the heap. This must be called before anything else.
		 */
		function init() {
// Load the Sbox lookup table
view8[0]=0x63; view8[1]=0x7c; view8[2]=0x77; view8[3]=0x7b; view8[4]=0xf2; view8[5]=0x6b;
view8[6]=0x6f; view8[7]=0xc5; view8[8]=0x30; view8[9]=0x01; view8[10]=0x67; view8[11]=0x2b;
view8[12]=0xfe; view8[13]=0xd7; view8[14]=0xab; view8[15]=0x76; view8[16]=0xca; view8[17]=0x82;
view8[18]=0xc9; view8[19]=0x7d; view8[20]=0xfa; view8[21]=0x59; view8[22]=0x47; view8[23]=0xf0;
view8[24]=0xad; view8[25]=0xd4; view8[26]=0xa2; view8[27]=0xaf; view8[28]=0x9c; view8[29]=0xa4;
view8[30]=0x72; view8[31]=0xc0; view8[32]=0xb7; view8[33]=0xfd; view8[34]=0x93; view8[35]=0x26;
view8[36]=0x36; view8[37]=0x3f; view8[38]=0xf7; view8[39]=0xcc; view8[40]=0x34; view8[41]=0xa5;
view8[42]=0xe5; view8[43]=0xf1; view8[44]=0x71; view8[45]=0xd8; view8[46]=0x31; view8[47]=0x15;
view8[48]=0x04; view8[49]=0xc7; view8[50]=0x23; view8[51]=0xc3; view8[52]=0x18; view8[53]=0x96;
view8[54]=0x05; view8[55]=0x9a; view8[56]=0x07; view8[57]=0x12; view8[58]=0x80; view8[59]=0xe2;
view8[60]=0xeb; view8[61]=0x27; view8[62]=0xb2; view8[63]=0x75; view8[64]=0x09; view8[65]=0x83;
view8[66]=0x2c; view8[67]=0x1a; view8[68]=0x1b; view8[69]=0x6e; view8[70]=0x5a; view8[71]=0xa0;
view8[72]=0x52; view8[73]=0x3b; view8[74]=0xd6; view8[75]=0xb3; view8[76]=0x29; view8[77]=0xe3;
view8[78]=0x2f; view8[79]=0x84; view8[80]=0x53; view8[81]=0xd1; view8[82]=0x00; view8[83]=0xed;
view8[84]=0x20; view8[85]=0xfc; view8[86]=0xb1; view8[87]=0x5b; view8[88]=0x6a; view8[89]=0xcb;
view8[90]=0xbe; view8[91]=0x39; view8[92]=0x4a; view8[93]=0x4c; view8[94]=0x58; view8[95]=0xcf;
view8[96]=0xd0; view8[97]=0xef; view8[98]=0xaa; view8[99]=0xfb; view8[100]=0x43; view8[101]=0x4d;
view8[102]=0x33; view8[103]=0x85; view8[104]=0x45; view8[105]=0xf9; view8[106]=0x02; view8[107]=0x7f;
view8[108]=0x50; view8[109]=0x3c; view8[110]=0x9f; view8[111]=0xa8; view8[112]=0x51; view8[113]=0xa3;
view8[114]=0x40; view8[115]=0x8f; view8[116]=0x92; view8[117]=0x9d; view8[118]=0x38; view8[119]=0xf5;
view8[120]=0xbc; view8[121]=0xb6; view8[122]=0xda; view8[123]=0x21; view8[124]=0x10; view8[125]=0xff;
view8[126]=0xf3; view8[127]=0xd2; view8[128]=0xcd; view8[129]=0x0c; view8[130]=0x13; view8[131]=0xec;
view8[132]=0x5f; view8[133]=0x97; view8[134]=0x44; view8[135]=0x17; view8[136]=0xc4; view8[137]=0xa7;
view8[138]=0x7e; view8[139]=0x3d; view8[140]=0x64; view8[141]=0x5d; view8[142]=0x19; view8[143]=0x73;
view8[144]=0x60; view8[145]=0x81; view8[146]=0x4f; view8[147]=0xdc; view8[148]=0x22; view8[149]=0x2a;
view8[150]=0x90; view8[151]=0x88; view8[152]=0x46; view8[153]=0xee; view8[154]=0xb8; view8[155]=0x14;
view8[156]=0xde; view8[157]=0x5e; view8[158]=0x0b; view8[159]=0xdb; view8[160]=0xe0; view8[161]=0x32;
view8[162]=0x3a; view8[163]=0x0a; view8[164]=0x49; view8[165]=0x06; view8[166]=0x24; view8[167]=0x5c;
view8[168]=0xc2; view8[169]=0xd3; view8[170]=0xac; view8[171]=0x62; view8[172]=0x91; view8[173]=0x95;
view8[174]=0xe4; view8[175]=0x79; view8[176]=0xe7; view8[177]=0xc8; view8[178]=0x37; view8[179]=0x6d;
view8[180]=0x8d; view8[181]=0xd5; view8[182]=0x4e; view8[183]=0xa9; view8[184]=0x6c; view8[185]=0x56;
view8[186]=0xf4; view8[187]=0xea; view8[188]=0x65; view8[189]=0x7a; view8[190]=0xae; view8[191]=0x08;
view8[192]=0xba; view8[193]=0x78; view8[194]=0x25; view8[195]=0x2e; view8[196]=0x1c; view8[197]=0xa6;
view8[198]=0xb4; view8[199]=0xc6; view8[200]=0xe8; view8[201]=0xdd; view8[202]=0x74; view8[203]=0x1f;
view8[204]=0x4b; view8[205]=0xbd; view8[206]=0x8b; view8[207]=0x8a; view8[208]=0x70; view8[209]=0x3e;
view8[210]=0xb5; view8[211]=0x66; view8[212]=0x48; view8[213]=0x03; view8[214]=0xf6; view8[215]=0x0e;
view8[216]=0x61; view8[217]=0x35; view8[218]=0x57; view8[219]=0xb9; view8[220]=0x86; view8[221]=0xc1;
view8[222]=0x1d; view8[223]=0x9e; view8[224]=0xe1; view8[225]=0xf8; view8[226]=0x98; view8[227]=0x11;
view8[228]=0x69; view8[229]=0xd9; view8[230]=0x8e; view8[231]=0x94; view8[232]=0x9b; view8[233]=0x1e;
view8[234]=0x87; view8[235]=0xe9; view8[236]=0xce; view8[237]=0x55; view8[238]=0x28; view8[239]=0xdf;
view8[240]=0x8c; view8[241]=0xa1; view8[242]=0x89; view8[243]=0x0d; view8[244]=0xbf; view8[245]=0xe6;
view8[246]=0x42; view8[247]=0x68; view8[248]=0x41; view8[249]=0x99; view8[250]=0x2d; view8[251]=0x0f;
view8[252]=0xb0; view8[253]=0x54; view8[254]=0xbb; view8[255]=0x16;
// Load the ISbox lookup table
view8[256]=0x52; view8[257]=0x09; view8[258]=0x6a; view8[259]=0xd5; view8[260]=0x30; view8[261]=0x36;
view8[262]=0xa5; view8[263]=0x38; view8[264]=0xbf; view8[265]=0x40; view8[266]=0xa3; view8[267]=0x9e;
view8[268]=0x81; view8[269]=0xf3; view8[270]=0xd7; view8[271]=0xfb; view8[272]=0x7c; view8[273]=0xe3;
view8[274]=0x39; view8[275]=0x82; view8[276]=0x9b; view8[277]=0x2f; view8[278]=0xff; view8[279]=0x87;
view8[280]=0x34; view8[281]=0x8e; view8[282]=0x43; view8[283]=0x44; view8[284]=0xc4; view8[285]=0xde;
view8[286]=0xe9; view8[287]=0xcb; view8[288]=0x54; view8[289]=0x7b; view8[290]=0x94; view8[291]=0x32;
view8[292]=0xa6; view8[293]=0xc2; view8[294]=0x23; view8[295]=0x3d; view8[296]=0xee; view8[297]=0x4c;
view8[298]=0x95; view8[299]=0x0b; view8[300]=0x42; view8[301]=0xfa; view8[302]=0xc3; view8[303]=0x4e;
view8[304]=0x08; view8[305]=0x2e; view8[306]=0xa1; view8[307]=0x66; view8[308]=0x28; view8[309]=0xd9;
view8[310]=0x24; view8[311]=0xb2; view8[312]=0x76; view8[313]=0x5b; view8[314]=0xa2; view8[315]=0x49;
view8[316]=0x6d; view8[317]=0x8b; view8[318]=0xd1; view8[319]=0x25; view8[320]=0x72; view8[321]=0xf8;
view8[322]=0xf6; view8[323]=0x64; view8[324]=0x86; view8[325]=0x68; view8[326]=0x98; view8[327]=0x16;
view8[328]=0xd4; view8[329]=0xa4; view8[330]=0x5c; view8[331]=0xcc; view8[332]=0x5d; view8[333]=0x65;
view8[334]=0xb6; view8[335]=0x92; view8[336]=0x6c; view8[337]=0x70; view8[338]=0x48; view8[339]=0x50;
view8[340]=0xfd; view8[341]=0xed; view8[342]=0xb9; view8[343]=0xda; view8[344]=0x5e; view8[345]=0x15;
view8[346]=0x46; view8[347]=0x57; view8[348]=0xa7; view8[349]=0x8d; view8[350]=0x9d; view8[351]=0x84;
view8[352]=0x90; view8[353]=0xd8; view8[354]=0xab; view8[355]=0x00; view8[356]=0x8c; view8[357]=0xbc;
view8[358]=0xd3; view8[359]=0x0a; view8[360]=0xf7; view8[361]=0xe4; view8[362]=0x58; view8[363]=0x05;
view8[364]=0xb8; view8[365]=0xb3; view8[366]=0x45; view8[367]=0x06; view8[368]=0xd0; view8[369]=0x2c;
view8[370]=0x1e; view8[371]=0x8f; view8[372]=0xca; view8[373]=0x3f; view8[374]=0x0f; view8[375]=0x02;
view8[376]=0xc1; view8[377]=0xaf; view8[378]=0xbd; view8[379]=0x03; view8[380]=0x01; view8[381]=0x13;
view8[382]=0x8a; view8[383]=0x6b; view8[384]=0x3a; view8[385]=0x91; view8[386]=0x11; view8[387]=0x41;
view8[388]=0x4f; view8[389]=0x67; view8[390]=0xdc; view8[391]=0xea; view8[392]=0x97; view8[393]=0xf2;
view8[394]=0xcf; view8[395]=0xce; view8[396]=0xf0; view8[397]=0xb4; view8[398]=0xe6; view8[399]=0x73;
view8[400]=0x96; view8[401]=0xac; view8[402]=0x74; view8[403]=0x22; view8[404]=0xe7; view8[405]=0xad;
view8[406]=0x35; view8[407]=0x85; view8[408]=0xe2; view8[409]=0xf9; view8[410]=0x37; view8[411]=0xe8;
view8[412]=0x1c; view8[413]=0x75; view8[414]=0xdf; view8[415]=0x6e; view8[416]=0x47; view8[417]=0xf1;
view8[418]=0x1a; view8[419]=0x71; view8[420]=0x1d; view8[421]=0x29; view8[422]=0xc5; view8[423]=0x89;
view8[424]=0x6f; view8[425]=0xb7; view8[426]=0x62; view8[427]=0x0e; view8[428]=0xaa; view8[429]=0x18;
view8[430]=0xbe; view8[431]=0x1b; view8[432]=0xfc; view8[433]=0x56; view8[434]=0x3e; view8[435]=0x4b;
view8[436]=0xc6; view8[437]=0xd2; view8[438]=0x79; view8[439]=0x20; view8[440]=0x9a; view8[441]=0xdb;
view8[442]=0xc0; view8[443]=0xfe; view8[444]=0x78; view8[445]=0xcd; view8[446]=0x5a; view8[447]=0xf4;
view8[448]=0x1f; view8[449]=0xdd; view8[450]=0xa8; view8[451]=0x33; view8[452]=0x88; view8[453]=0x07;
view8[454]=0xc7; view8[455]=0x31; view8[456]=0xb1; view8[457]=0x12; view8[458]=0x10; view8[459]=0x59;
view8[460]=0x27; view8[461]=0x80; view8[462]=0xec; view8[463]=0x5f; view8[464]=0x60; view8[465]=0x51;
view8[466]=0x7f; view8[467]=0xa9; view8[468]=0x19; view8[469]=0xb5; view8[470]=0x4a; view8[471]=0x0d;
view8[472]=0x2d; view8[473]=0xe5; view8[474]=0x7a; view8[475]=0x9f; view8[476]=0x93; view8[477]=0xc9;
view8[478]=0x9c; view8[479]=0xef; view8[480]=0xa0; view8[481]=0xe0; view8[482]=0x3b; view8[483]=0x4d;
view8[484]=0xae; view8[485]=0x2a; view8[486]=0xf5; view8[487]=0xb0; view8[488]=0xc8; view8[489]=0xeb;
view8[490]=0xbb; view8[491]=0x3c; view8[492]=0x83; view8[493]=0x53; view8[494]=0x99; view8[495]=0x61;
view8[496]=0x17; view8[497]=0x2b; view8[498]=0x04; view8[499]=0x7e; view8[500]=0xba; view8[501]=0x77;
view8[502]=0xd6; view8[503]=0x26; view8[504]=0xe1; view8[505]=0x69; view8[506]=0x14; view8[507]=0x63;
view8[508]=0x55; view8[509]=0x21; view8[510]=0x0c; view8[511]=0x7d;
// Load the Xtime2Sbox lookup table
view8[512]=0xc6; view8[513]=0xf8; view8[514]=0xee; view8[515]=0xf6; view8[516]=0xff; view8[517]=0xd6;
view8[518]=0xde; view8[519]=0x91; view8[520]=0x60; view8[521]=0x02; view8[522]=0xce; view8[523]=0x56;
view8[524]=0xe7; view8[525]=0xb5; view8[526]=0x4d; view8[527]=0xec; view8[528]=0x8f; view8[529]=0x1f;
view8[530]=0x89; view8[531]=0xfa; view8[532]=0xef; view8[533]=0xb2; view8[534]=0x8e; view8[535]=0xfb;
view8[536]=0x41; view8[537]=0xb3; view8[538]=0x5f; view8[539]=0x45; view8[540]=0x23; view8[541]=0x53;
view8[542]=0xe4; view8[543]=0x9b; view8[544]=0x75; view8[545]=0xe1; view8[546]=0x3d; view8[547]=0x4c;
view8[548]=0x6c; view8[549]=0x7e; view8[550]=0xf5; view8[551]=0x83; view8[552]=0x68; view8[553]=0x51;
view8[554]=0xd1; view8[555]=0xf9; view8[556]=0xe2; view8[557]=0xab; view8[558]=0x62; view8[559]=0x2a;
view8[560]=0x08; view8[561]=0x95; view8[562]=0x46; view8[563]=0x9d; view8[564]=0x30; view8[565]=0x37;
view8[566]=0x0a; view8[567]=0x2f; view8[568]=0x0e; view8[569]=0x24; view8[570]=0x1b; view8[571]=0xdf;
view8[572]=0xcd; view8[573]=0x4e; view8[574]=0x7f; view8[575]=0xea; view8[576]=0x12; view8[577]=0x1d;
view8[578]=0x58; view8[579]=0x34; view8[580]=0x36; view8[581]=0xdc; view8[582]=0xb4; view8[583]=0x5b;
view8[584]=0xa4; view8[585]=0x76; view8[586]=0xb7; view8[587]=0x7d; view8[588]=0x52; view8[589]=0xdd;
view8[590]=0x5e; view8[591]=0x13; view8[592]=0xa6; view8[593]=0xb9; view8[594]=0x00; view8[595]=0xc1;
view8[596]=0x40; view8[597]=0xe3; view8[598]=0x79; view8[599]=0xb6; view8[600]=0xd4; view8[601]=0x8d;
view8[602]=0x67; view8[603]=0x72; view8[604]=0x94; view8[605]=0x98; view8[606]=0xb0; view8[607]=0x85;
view8[608]=0xbb; view8[609]=0xc5; view8[610]=0x4f; view8[611]=0xed; view8[612]=0x86; view8[613]=0x9a;
view8[614]=0x66; view8[615]=0x11; view8[616]=0x8a; view8[617]=0xe9; view8[618]=0x04; view8[619]=0xfe;
view8[620]=0xa0; view8[621]=0x78; view8[622]=0x25; view8[623]=0x4b; view8[624]=0xa2; view8[625]=0x5d;
view8[626]=0x80; view8[627]=0x05; view8[628]=0x3f; view8[629]=0x21; view8[630]=0x70; view8[631]=0xf1;
view8[632]=0x63; view8[633]=0x77; view8[634]=0xaf; view8[635]=0x42; view8[636]=0x20; view8[637]=0xe5;
view8[638]=0xfd; view8[639]=0xbf; view8[640]=0x81; view8[641]=0x18; view8[642]=0x26; view8[643]=0xc3;
view8[644]=0xbe; view8[645]=0x35; view8[646]=0x88; view8[647]=0x2e; view8[648]=0x93; view8[649]=0x55;
view8[650]=0xfc; view8[651]=0x7a; view8[652]=0xc8; view8[653]=0xba; view8[654]=0x32; view8[655]=0xe6;
view8[656]=0xc0; view8[657]=0x19; view8[658]=0x9e; view8[659]=0xa3; view8[660]=0x44; view8[661]=0x54;
view8[662]=0x3b; view8[663]=0x0b; view8[664]=0x8c; view8[665]=0xc7; view8[666]=0x6b; view8[667]=0x28;
view8[668]=0xa7; view8[669]=0xbc; view8[670]=0x16; view8[671]=0xad; view8[672]=0xdb; view8[673]=0x64;
view8[674]=0x74; view8[675]=0x14; view8[676]=0x92; view8[677]=0x0c; view8[678]=0x48; view8[679]=0xb8;
view8[680]=0x9f; view8[681]=0xbd; view8[682]=0x43; view8[683]=0xc4; view8[684]=0x39; view8[685]=0x31;
view8[686]=0xd3; view8[687]=0xf2; view8[688]=0xd5; view8[689]=0x8b; view8[690]=0x6e; view8[691]=0xda;
view8[692]=0x01; view8[693]=0xb1; view8[694]=0x9c; view8[695]=0x49; view8[696]=0xd8; view8[697]=0xac;
view8[698]=0xf3; view8[699]=0xcf; view8[700]=0xca; view8[701]=0xf4; view8[702]=0x47; view8[703]=0x10;
view8[704]=0x6f; view8[705]=0xf0; view8[706]=0x4a; view8[707]=0x5c; view8[708]=0x38; view8[709]=0x57;
view8[710]=0x73; view8[711]=0x97; view8[712]=0xcb; view8[713]=0xa1; view8[714]=0xe8; view8[715]=0x3e;
view8[716]=0x96; view8[717]=0x61; view8[718]=0x0d; view8[719]=0x0f; view8[720]=0xe0; view8[721]=0x7c;
view8[722]=0x71; view8[723]=0xcc; view8[724]=0x90; view8[725]=0x06; view8[726]=0xf7; view8[727]=0x1c;
view8[728]=0xc2; view8[729]=0x6a; view8[730]=0xae; view8[731]=0x69; view8[732]=0x17; view8[733]=0x99;
view8[734]=0x3a; view8[735]=0x27; view8[736]=0xd9; view8[737]=0xeb; view8[738]=0x2b; view8[739]=0x22;
view8[740]=0xd2; view8[741]=0xa9; view8[742]=0x07; view8[743]=0x33; view8[744]=0x2d; view8[745]=0x3c;
view8[746]=0x15; view8[747]=0xc9; view8[748]=0x87; view8[749]=0xaa; view8[750]=0x50; view8[751]=0xa5;
view8[752]=0x03; view8[753]=0x59; view8[754]=0x09; view8[755]=0x1a; view8[756]=0x65; view8[757]=0xd7;
view8[758]=0x84; view8[759]=0xd0; view8[760]=0x82; view8[761]=0x29; view8[762]=0x5a; view8[763]=0x1e;
view8[764]=0x7b; view8[765]=0xa8; view8[766]=0x6d; view8[767]=0x2c;
// Load the Xtime3Sbox lookup table
view8[768]=0xa5; view8[769]=0x84; view8[770]=0x99; view8[771]=0x8d; view8[772]=0x0d; view8[773]=0xbd;
view8[774]=0xb1; view8[775]=0x54; view8[776]=0x50; view8[777]=0x03; view8[778]=0xa9; view8[779]=0x7d;
view8[780]=0x19; view8[781]=0x62; view8[782]=0xe6; view8[783]=0x9a; view8[784]=0x45; view8[785]=0x9d;
view8[786]=0x40; view8[787]=0x87; view8[788]=0x15; view8[789]=0xeb; view8[790]=0xc9; view8[791]=0x0b;
view8[792]=0xec; view8[793]=0x67; view8[794]=0xfd; view8[795]=0xea; view8[796]=0xbf; view8[797]=0xf7;
view8[798]=0x96; view8[799]=0x5b; view8[800]=0xc2; view8[801]=0x1c; view8[802]=0xae; view8[803]=0x6a;
view8[804]=0x5a; view8[805]=0x41; view8[806]=0x02; view8[807]=0x4f; view8[808]=0x5c; view8[809]=0xf4;
view8[810]=0x34; view8[811]=0x08; view8[812]=0x93; view8[813]=0x73; view8[814]=0x53; view8[815]=0x3f;
view8[816]=0x0c; view8[817]=0x52; view8[818]=0x65; view8[819]=0x5e; view8[820]=0x28; view8[821]=0xa1;
view8[822]=0x0f; view8[823]=0xb5; view8[824]=0x09; view8[825]=0x36; view8[826]=0x9b; view8[827]=0x3d;
view8[828]=0x26; view8[829]=0x69; view8[830]=0xcd; view8[831]=0x9f; view8[832]=0x1b; view8[833]=0x9e;
view8[834]=0x74; view8[835]=0x2e; view8[836]=0x2d; view8[837]=0xb2; view8[838]=0xee; view8[839]=0xfb;
view8[840]=0xf6; view8[841]=0x4d; view8[842]=0x61; view8[843]=0xce; view8[844]=0x7b; view8[845]=0x3e;
view8[846]=0x71; view8[847]=0x97; view8[848]=0xf5; view8[849]=0x68; view8[850]=0x00; view8[851]=0x2c;
view8[852]=0x60; view8[853]=0x1f; view8[854]=0xc8; view8[855]=0xed; view8[856]=0xbe; view8[857]=0x46;
view8[858]=0xd9; view8[859]=0x4b; view8[860]=0xde; view8[861]=0xd4; view8[862]=0xe8; view8[863]=0x4a;
view8[864]=0x6b; view8[865]=0x2a; view8[866]=0xe5; view8[867]=0x16; view8[868]=0xc5; view8[869]=0xd7;
view8[870]=0x55; view8[871]=0x94; view8[872]=0xcf; view8[873]=0x10; view8[874]=0x06; view8[875]=0x81;
view8[876]=0xf0; view8[877]=0x44; view8[878]=0xba; view8[879]=0xe3; view8[880]=0xf3; view8[881]=0xfe;
view8[882]=0xc0; view8[883]=0x8a; view8[884]=0xad; view8[885]=0xbc; view8[886]=0x48; view8[887]=0x04;
view8[888]=0xdf; view8[889]=0xc1; view8[890]=0x75; view8[891]=0x63; view8[892]=0x30; view8[893]=0x1a;
view8[894]=0x0e; view8[895]=0x6d; view8[896]=0x4c; view8[897]=0x14; view8[898]=0x35; view8[899]=0x2f;
view8[900]=0xe1; view8[901]=0xa2; view8[902]=0xcc; view8[903]=0x39; view8[904]=0x57; view8[905]=0xf2;
view8[906]=0x82; view8[907]=0x47; view8[908]=0xac; view8[909]=0xe7; view8[910]=0x2b; view8[911]=0x95;
view8[912]=0xa0; view8[913]=0x98; view8[914]=0xd1; view8[915]=0x7f; view8[916]=0x66; view8[917]=0x7e;
view8[918]=0xab; view8[919]=0x83; view8[920]=0xca; view8[921]=0x29; view8[922]=0xd3; view8[923]=0x3c;
view8[924]=0x79; view8[925]=0xe2; view8[926]=0x1d; view8[927]=0x76; view8[928]=0x3b; view8[929]=0x56;
view8[930]=0x4e; view8[931]=0x1e; view8[932]=0xdb; view8[933]=0x0a; view8[934]=0x6c; view8[935]=0xe4;
view8[936]=0x5d; view8[937]=0x6e; view8[938]=0xef; view8[939]=0xa6; view8[940]=0xa8; view8[941]=0xa4;
view8[942]=0x37; view8[943]=0x8b; view8[944]=0x32; view8[945]=0x43; view8[946]=0x59; view8[947]=0xb7;
view8[948]=0x8c; view8[949]=0x64; view8[950]=0xd2; view8[951]=0xe0; view8[952]=0xb4; view8[953]=0xfa;
view8[954]=0x07; view8[955]=0x25; view8[956]=0xaf; view8[957]=0x8e; view8[958]=0xe9; view8[959]=0x18;
view8[960]=0xd5; view8[961]=0x88; view8[962]=0x6f; view8[963]=0x72; view8[964]=0x24; view8[965]=0xf1;
view8[966]=0xc7; view8[967]=0x51; view8[968]=0x23; view8[969]=0x7c; view8[970]=0x9c; view8[971]=0x21;
view8[972]=0xdd; view8[973]=0xdc; view8[974]=0x86; view8[975]=0x85; view8[976]=0x90; view8[977]=0x42;
view8[978]=0xc4; view8[979]=0xaa; view8[980]=0xd8; view8[981]=0x05; view8[982]=0x01; view8[983]=0x12;
view8[984]=0xa3; view8[985]=0x5f; view8[986]=0xf9; view8[987]=0xd0; view8[988]=0x91; view8[989]=0x58;
view8[990]=0x27; view8[991]=0xb9; view8[992]=0x38; view8[993]=0x13; view8[994]=0xb3; view8[995]=0x33;
view8[996]=0xbb; view8[997]=0x70; view8[998]=0x89; view8[999]=0xa7; view8[1000]=0xb6; view8[1001]=0x22;
view8[1002]=0x92; view8[1003]=0x20; view8[1004]=0x49; view8[1005]=0xff; view8[1006]=0x78; view8[1007]=0x7a;
view8[1008]=0x8f; view8[1009]=0xf8; view8[1010]=0x80; view8[1011]=0x17; view8[1012]=0xda; view8[1013]=0x31;
view8[1014]=0xc6; view8[1015]=0xb8; view8[1016]=0xc3; view8[1017]=0xb0; view8[1018]=0x77; view8[1019]=0x11;
view8[1020]=0xcb; view8[1021]=0xfc; view8[1022]=0xd6; view8[1023]=0x3a;
// Load the Xtime9 lookup table
view8[1024]=0x00; view8[1025]=0x09; view8[1026]=0x12; view8[1027]=0x1b; view8[1028]=0x24; view8[1029]=0x2d;
view8[1030]=0x36; view8[1031]=0x3f; view8[1032]=0x48; view8[1033]=0x41; view8[1034]=0x5a; view8[1035]=0x53;
view8[1036]=0x6c; view8[1037]=0x65; view8[1038]=0x7e; view8[1039]=0x77; view8[1040]=0x90; view8[1041]=0x99;
view8[1042]=0x82; view8[1043]=0x8b; view8[1044]=0xb4; view8[1045]=0xbd; view8[1046]=0xa6; view8[1047]=0xaf;
view8[1048]=0xd8; view8[1049]=0xd1; view8[1050]=0xca; view8[1051]=0xc3; view8[1052]=0xfc; view8[1053]=0xf5;
view8[1054]=0xee; view8[1055]=0xe7; view8[1056]=0x3b; view8[1057]=0x32; view8[1058]=0x29; view8[1059]=0x20;
view8[1060]=0x1f; view8[1061]=0x16; view8[1062]=0x0d; view8[1063]=0x04; view8[1064]=0x73; view8[1065]=0x7a;
view8[1066]=0x61; view8[1067]=0x68; view8[1068]=0x57; view8[1069]=0x5e; view8[1070]=0x45; view8[1071]=0x4c;
view8[1072]=0xab; view8[1073]=0xa2; view8[1074]=0xb9; view8[1075]=0xb0; view8[1076]=0x8f; view8[1077]=0x86;
view8[1078]=0x9d; view8[1079]=0x94; view8[1080]=0xe3; view8[1081]=0xea; view8[1082]=0xf1; view8[1083]=0xf8;
view8[1084]=0xc7; view8[1085]=0xce; view8[1086]=0xd5; view8[1087]=0xdc; view8[1088]=0x76; view8[1089]=0x7f;
view8[1090]=0x64; view8[1091]=0x6d; view8[1092]=0x52; view8[1093]=0x5b; view8[1094]=0x40; view8[1095]=0x49;
view8[1096]=0x3e; view8[1097]=0x37; view8[1098]=0x2c; view8[1099]=0x25; view8[1100]=0x1a; view8[1101]=0x13;
view8[1102]=0x08; view8[1103]=0x01; view8[1104]=0xe6; view8[1105]=0xef; view8[1106]=0xf4; view8[1107]=0xfd;
view8[1108]=0xc2; view8[1109]=0xcb; view8[1110]=0xd0; view8[1111]=0xd9; view8[1112]=0xae; view8[1113]=0xa7;
view8[1114]=0xbc; view8[1115]=0xb5; view8[1116]=0x8a; view8[1117]=0x83; view8[1118]=0x98; view8[1119]=0x91;
view8[1120]=0x4d; view8[1121]=0x44; view8[1122]=0x5f; view8[1123]=0x56; view8[1124]=0x69; view8[1125]=0x60;
view8[1126]=0x7b; view8[1127]=0x72; view8[1128]=0x05; view8[1129]=0x0c; view8[1130]=0x17; view8[1131]=0x1e;
view8[1132]=0x21; view8[1133]=0x28; view8[1134]=0x33; view8[1135]=0x3a; view8[1136]=0xdd; view8[1137]=0xd4;
view8[1138]=0xcf; view8[1139]=0xc6; view8[1140]=0xf9; view8[1141]=0xf0; view8[1142]=0xeb; view8[1143]=0xe2;
view8[1144]=0x95; view8[1145]=0x9c; view8[1146]=0x87; view8[1147]=0x8e; view8[1148]=0xb1; view8[1149]=0xb8;
view8[1150]=0xa3; view8[1151]=0xaa; view8[1152]=0xec; view8[1153]=0xe5; view8[1154]=0xfe; view8[1155]=0xf7;
view8[1156]=0xc8; view8[1157]=0xc1; view8[1158]=0xda; view8[1159]=0xd3; view8[1160]=0xa4; view8[1161]=0xad;
view8[1162]=0xb6; view8[1163]=0xbf; view8[1164]=0x80; view8[1165]=0x89; view8[1166]=0x92; view8[1167]=0x9b;
view8[1168]=0x7c; view8[1169]=0x75; view8[1170]=0x6e; view8[1171]=0x67; view8[1172]=0x58; view8[1173]=0x51;
view8[1174]=0x4a; view8[1175]=0x43; view8[1176]=0x34; view8[1177]=0x3d; view8[1178]=0x26; view8[1179]=0x2f;
view8[1180]=0x10; view8[1181]=0x19; view8[1182]=0x02; view8[1183]=0x0b; view8[1184]=0xd7; view8[1185]=0xde;
view8[1186]=0xc5; view8[1187]=0xcc; view8[1188]=0xf3; view8[1189]=0xfa; view8[1190]=0xe1; view8[1191]=0xe8;
view8[1192]=0x9f; view8[1193]=0x96; view8[1194]=0x8d; view8[1195]=0x84; view8[1196]=0xbb; view8[1197]=0xb2;
view8[1198]=0xa9; view8[1199]=0xa0; view8[1200]=0x47; view8[1201]=0x4e; view8[1202]=0x55; view8[1203]=0x5c;
view8[1204]=0x63; view8[1205]=0x6a; view8[1206]=0x71; view8[1207]=0x78; view8[1208]=0x0f; view8[1209]=0x06;
view8[1210]=0x1d; view8[1211]=0x14; view8[1212]=0x2b; view8[1213]=0x22; view8[1214]=0x39; view8[1215]=0x30;
view8[1216]=0x9a; view8[1217]=0x93; view8[1218]=0x88; view8[1219]=0x81; view8[1220]=0xbe; view8[1221]=0xb7;
view8[1222]=0xac; view8[1223]=0xa5; view8[1224]=0xd2; view8[1225]=0xdb; view8[1226]=0xc0; view8[1227]=0xc9;
view8[1228]=0xf6; view8[1229]=0xff; view8[1230]=0xe4; view8[1231]=0xed; view8[1232]=0x0a; view8[1233]=0x03;
view8[1234]=0x18; view8[1235]=0x11; view8[1236]=0x2e; view8[1237]=0x27; view8[1238]=0x3c; view8[1239]=0x35;
view8[1240]=0x42; view8[1241]=0x4b; view8[1242]=0x50; view8[1243]=0x59; view8[1244]=0x66; view8[1245]=0x6f;
view8[1246]=0x74; view8[1247]=0x7d; view8[1248]=0xa1; view8[1249]=0xa8; view8[1250]=0xb3; view8[1251]=0xba;
view8[1252]=0x85; view8[1253]=0x8c; view8[1254]=0x97; view8[1255]=0x9e; view8[1256]=0xe9; view8[1257]=0xe0;
view8[1258]=0xfb; view8[1259]=0xf2; view8[1260]=0xcd; view8[1261]=0xc4; view8[1262]=0xdf; view8[1263]=0xd6;
view8[1264]=0x31; view8[1265]=0x38; view8[1266]=0x23; view8[1267]=0x2a; view8[1268]=0x15; view8[1269]=0x1c;
view8[1270]=0x07; view8[1271]=0x0e; view8[1272]=0x79; view8[1273]=0x70; view8[1274]=0x6b; view8[1275]=0x62;
view8[1276]=0x5d; view8[1277]=0x54; view8[1278]=0x4f; view8[1279]=0x46;
// Load the XtimeB lookup table
view8[1280]=0x00; view8[1281]=0x0b; view8[1282]=0x16; view8[1283]=0x1d; view8[1284]=0x2c; view8[1285]=0x27;
view8[1286]=0x3a; view8[1287]=0x31; view8[1288]=0x58; view8[1289]=0x53; view8[1290]=0x4e; view8[1291]=0x45;
view8[1292]=0x74; view8[1293]=0x7f; view8[1294]=0x62; view8[1295]=0x69; view8[1296]=0xb0; view8[1297]=0xbb;
view8[1298]=0xa6; view8[1299]=0xad; view8[1300]=0x9c; view8[1301]=0x97; view8[1302]=0x8a; view8[1303]=0x81;
view8[1304]=0xe8; view8[1305]=0xe3; view8[1306]=0xfe; view8[1307]=0xf5; view8[1308]=0xc4; view8[1309]=0xcf;
view8[1310]=0xd2; view8[1311]=0xd9; view8[1312]=0x7b; view8[1313]=0x70; view8[1314]=0x6d; view8[1315]=0x66;
view8[1316]=0x57; view8[1317]=0x5c; view8[1318]=0x41; view8[1319]=0x4a; view8[1320]=0x23; view8[1321]=0x28;
view8[1322]=0x35; view8[1323]=0x3e; view8[1324]=0x0f; view8[1325]=0x04; view8[1326]=0x19; view8[1327]=0x12;
view8[1328]=0xcb; view8[1329]=0xc0; view8[1330]=0xdd; view8[1331]=0xd6; view8[1332]=0xe7; view8[1333]=0xec;
view8[1334]=0xf1; view8[1335]=0xfa; view8[1336]=0x93; view8[1337]=0x98; view8[1338]=0x85; view8[1339]=0x8e;
view8[1340]=0xbf; view8[1341]=0xb4; view8[1342]=0xa9; view8[1343]=0xa2; view8[1344]=0xf6; view8[1345]=0xfd;
view8[1346]=0xe0; view8[1347]=0xeb; view8[1348]=0xda; view8[1349]=0xd1; view8[1350]=0xcc; view8[1351]=0xc7;
view8[1352]=0xae; view8[1353]=0xa5; view8[1354]=0xb8; view8[1355]=0xb3; view8[1356]=0x82; view8[1357]=0x89;
view8[1358]=0x94; view8[1359]=0x9f; view8[1360]=0x46; view8[1361]=0x4d; view8[1362]=0x50; view8[1363]=0x5b;
view8[1364]=0x6a; view8[1365]=0x61; view8[1366]=0x7c; view8[1367]=0x77; view8[1368]=0x1e; view8[1369]=0x15;
view8[1370]=0x08; view8[1371]=0x03; view8[1372]=0x32; view8[1373]=0x39; view8[1374]=0x24; view8[1375]=0x2f;
view8[1376]=0x8d; view8[1377]=0x86; view8[1378]=0x9b; view8[1379]=0x90; view8[1380]=0xa1; view8[1381]=0xaa;
view8[1382]=0xb7; view8[1383]=0xbc; view8[1384]=0xd5; view8[1385]=0xde; view8[1386]=0xc3; view8[1387]=0xc8;
view8[1388]=0xf9; view8[1389]=0xf2; view8[1390]=0xef; view8[1391]=0xe4; view8[1392]=0x3d; view8[1393]=0x36;
view8[1394]=0x2b; view8[1395]=0x20; view8[1396]=0x11; view8[1397]=0x1a; view8[1398]=0x07; view8[1399]=0x0c;
view8[1400]=0x65; view8[1401]=0x6e; view8[1402]=0x73; view8[1403]=0x78; view8[1404]=0x49; view8[1405]=0x42;
view8[1406]=0x5f; view8[1407]=0x54; view8[1408]=0xf7; view8[1409]=0xfc; view8[1410]=0xe1; view8[1411]=0xea;
view8[1412]=0xdb; view8[1413]=0xd0; view8[1414]=0xcd; view8[1415]=0xc6; view8[1416]=0xaf; view8[1417]=0xa4;
view8[1418]=0xb9; view8[1419]=0xb2; view8[1420]=0x83; view8[1421]=0x88; view8[1422]=0x95; view8[1423]=0x9e;
view8[1424]=0x47; view8[1425]=0x4c; view8[1426]=0x51; view8[1427]=0x5a; view8[1428]=0x6b; view8[1429]=0x60;
view8[1430]=0x7d; view8[1431]=0x76; view8[1432]=0x1f; view8[1433]=0x14; view8[1434]=0x09; view8[1435]=0x02;
view8[1436]=0x33; view8[1437]=0x38; view8[1438]=0x25; view8[1439]=0x2e; view8[1440]=0x8c; view8[1441]=0x87;
view8[1442]=0x9a; view8[1443]=0x91; view8[1444]=0xa0; view8[1445]=0xab; view8[1446]=0xb6; view8[1447]=0xbd;
view8[1448]=0xd4; view8[1449]=0xdf; view8[1450]=0xc2; view8[1451]=0xc9; view8[1452]=0xf8; view8[1453]=0xf3;
view8[1454]=0xee; view8[1455]=0xe5; view8[1456]=0x3c; view8[1457]=0x37; view8[1458]=0x2a; view8[1459]=0x21;
view8[1460]=0x10; view8[1461]=0x1b; view8[1462]=0x06; view8[1463]=0x0d; view8[1464]=0x64; view8[1465]=0x6f;
view8[1466]=0x72; view8[1467]=0x79; view8[1468]=0x48; view8[1469]=0x43; view8[1470]=0x5e; view8[1471]=0x55;
view8[1472]=0x01; view8[1473]=0x0a; view8[1474]=0x17; view8[1475]=0x1c; view8[1476]=0x2d; view8[1477]=0x26;
view8[1478]=0x3b; view8[1479]=0x30; view8[1480]=0x59; view8[1481]=0x52; view8[1482]=0x4f; view8[1483]=0x44;
view8[1484]=0x75; view8[1485]=0x7e; view8[1486]=0x63; view8[1487]=0x68; view8[1488]=0xb1; view8[1489]=0xba;
view8[1490]=0xa7; view8[1491]=0xac; view8[1492]=0x9d; view8[1493]=0x96; view8[1494]=0x8b; view8[1495]=0x80;
view8[1496]=0xe9; view8[1497]=0xe2; view8[1498]=0xff; view8[1499]=0xf4; view8[1500]=0xc5; view8[1501]=0xce;
view8[1502]=0xd3; view8[1503]=0xd8; view8[1504]=0x7a; view8[1505]=0x71; view8[1506]=0x6c; view8[1507]=0x67;
view8[1508]=0x56; view8[1509]=0x5d; view8[1510]=0x40; view8[1511]=0x4b; view8[1512]=0x22; view8[1513]=0x29;
view8[1514]=0x34; view8[1515]=0x3f; view8[1516]=0x0e; view8[1517]=0x05; view8[1518]=0x18; view8[1519]=0x13;
view8[1520]=0xca; view8[1521]=0xc1; view8[1522]=0xdc; view8[1523]=0xd7; view8[1524]=0xe6; view8[1525]=0xed;
view8[1526]=0xf0; view8[1527]=0xfb; view8[1528]=0x92; view8[1529]=0x99; view8[1530]=0x84; view8[1531]=0x8f;
view8[1532]=0xbe; view8[1533]=0xb5; view8[1534]=0xa8; view8[1535]=0xa3;
// Load the XtimeD lookup table
view8[1536]=0x00; view8[1537]=0x0d; view8[1538]=0x1a; view8[1539]=0x17; view8[1540]=0x34; view8[1541]=0x39;
view8[1542]=0x2e; view8[1543]=0x23; view8[1544]=0x68; view8[1545]=0x65; view8[1546]=0x72; view8[1547]=0x7f;
view8[1548]=0x5c; view8[1549]=0x51; view8[1550]=0x46; view8[1551]=0x4b; view8[1552]=0xd0; view8[1553]=0xdd;
view8[1554]=0xca; view8[1555]=0xc7; view8[1556]=0xe4; view8[1557]=0xe9; view8[1558]=0xfe; view8[1559]=0xf3;
view8[1560]=0xb8; view8[1561]=0xb5; view8[1562]=0xa2; view8[1563]=0xaf; view8[1564]=0x8c; view8[1565]=0x81;
view8[1566]=0x96; view8[1567]=0x9b; view8[1568]=0xbb; view8[1569]=0xb6; view8[1570]=0xa1; view8[1571]=0xac;
view8[1572]=0x8f; view8[1573]=0x82; view8[1574]=0x95; view8[1575]=0x98; view8[1576]=0xd3; view8[1577]=0xde;
view8[1578]=0xc9; view8[1579]=0xc4; view8[1580]=0xe7; view8[1581]=0xea; view8[1582]=0xfd; view8[1583]=0xf0;
view8[1584]=0x6b; view8[1585]=0x66; view8[1586]=0x71; view8[1587]=0x7c; view8[1588]=0x5f; view8[1589]=0x52;
view8[1590]=0x45; view8[1591]=0x48; view8[1592]=0x03; view8[1593]=0x0e; view8[1594]=0x19; view8[1595]=0x14;
view8[1596]=0x37; view8[1597]=0x3a; view8[1598]=0x2d; view8[1599]=0x20; view8[1600]=0x6d; view8[1601]=0x60;
view8[1602]=0x77; view8[1603]=0x7a; view8[1604]=0x59; view8[1605]=0x54; view8[1606]=0x43; view8[1607]=0x4e;
view8[1608]=0x05; view8[1609]=0x08; view8[1610]=0x1f; view8[1611]=0x12; view8[1612]=0x31; view8[1613]=0x3c;
view8[1614]=0x2b; view8[1615]=0x26; view8[1616]=0xbd; view8[1617]=0xb0; view8[1618]=0xa7; view8[1619]=0xaa;
view8[1620]=0x89; view8[1621]=0x84; view8[1622]=0x93; view8[1623]=0x9e; view8[1624]=0xd5; view8[1625]=0xd8;
view8[1626]=0xcf; view8[1627]=0xc2; view8[1628]=0xe1; view8[1629]=0xec; view8[1630]=0xfb; view8[1631]=0xf6;
view8[1632]=0xd6; view8[1633]=0xdb; view8[1634]=0xcc; view8[1635]=0xc1; view8[1636]=0xe2; view8[1637]=0xef;
view8[1638]=0xf8; view8[1639]=0xf5; view8[1640]=0xbe; view8[1641]=0xb3; view8[1642]=0xa4; view8[1643]=0xa9;
view8[1644]=0x8a; view8[1645]=0x87; view8[1646]=0x90; view8[1647]=0x9d; view8[1648]=0x06; view8[1649]=0x0b;
view8[1650]=0x1c; view8[1651]=0x11; view8[1652]=0x32; view8[1653]=0x3f; view8[1654]=0x28; view8[1655]=0x25;
view8[1656]=0x6e; view8[1657]=0x63; view8[1658]=0x74; view8[1659]=0x79; view8[1660]=0x5a; view8[1661]=0x57;
view8[1662]=0x40; view8[1663]=0x4d; view8[1664]=0xda; view8[1665]=0xd7; view8[1666]=0xc0; view8[1667]=0xcd;
view8[1668]=0xee; view8[1669]=0xe3; view8[1670]=0xf4; view8[1671]=0xf9; view8[1672]=0xb2; view8[1673]=0xbf;
view8[1674]=0xa8; view8[1675]=0xa5; view8[1676]=0x86; view8[1677]=0x8b; view8[1678]=0x9c; view8[1679]=0x91;
view8[1680]=0x0a; view8[1681]=0x07; view8[1682]=0x10; view8[1683]=0x1d; view8[1684]=0x3e; view8[1685]=0x33;
view8[1686]=0x24; view8[1687]=0x29; view8[1688]=0x62; view8[1689]=0x6f; view8[1690]=0x78; view8[1691]=0x75;
view8[1692]=0x56; view8[1693]=0x5b; view8[1694]=0x4c; view8[1695]=0x41; view8[1696]=0x61; view8[1697]=0x6c;
view8[1698]=0x7b; view8[1699]=0x76; view8[1700]=0x55; view8[1701]=0x58; view8[1702]=0x4f; view8[1703]=0x42;
view8[1704]=0x09; view8[1705]=0x04; view8[1706]=0x13; view8[1707]=0x1e; view8[1708]=0x3d; view8[1709]=0x30;
view8[1710]=0x27; view8[1711]=0x2a; view8[1712]=0xb1; view8[1713]=0xbc; view8[1714]=0xab; view8[1715]=0xa6;
view8[1716]=0x85; view8[1717]=0x88; view8[1718]=0x9f; view8[1719]=0x92; view8[1720]=0xd9; view8[1721]=0xd4;
view8[1722]=0xc3; view8[1723]=0xce; view8[1724]=0xed; view8[1725]=0xe0; view8[1726]=0xf7; view8[1727]=0xfa;
view8[1728]=0xb7; view8[1729]=0xba; view8[1730]=0xad; view8[1731]=0xa0; view8[1732]=0x83; view8[1733]=0x8e;
view8[1734]=0x99; view8[1735]=0x94; view8[1736]=0xdf; view8[1737]=0xd2; view8[1738]=0xc5; view8[1739]=0xc8;
view8[1740]=0xeb; view8[1741]=0xe6; view8[1742]=0xf1; view8[1743]=0xfc; view8[1744]=0x67; view8[1745]=0x6a;
view8[1746]=0x7d; view8[1747]=0x70; view8[1748]=0x53; view8[1749]=0x5e; view8[1750]=0x49; view8[1751]=0x44;
view8[1752]=0x0f; view8[1753]=0x02; view8[1754]=0x15; view8[1755]=0x18; view8[1756]=0x3b; view8[1757]=0x36;
view8[1758]=0x21; view8[1759]=0x2c; view8[1760]=0x0c; view8[1761]=0x01; view8[1762]=0x16; view8[1763]=0x1b;
view8[1764]=0x38; view8[1765]=0x35; view8[1766]=0x22; view8[1767]=0x2f; view8[1768]=0x64; view8[1769]=0x69;
view8[1770]=0x7e; view8[1771]=0x73; view8[1772]=0x50; view8[1773]=0x5d; view8[1774]=0x4a; view8[1775]=0x47;
view8[1776]=0xdc; view8[1777]=0xd1; view8[1778]=0xc6; view8[1779]=0xcb; view8[1780]=0xe8; view8[1781]=0xe5;
view8[1782]=0xf2; view8[1783]=0xff; view8[1784]=0xb4; view8[1785]=0xb9; view8[1786]=0xae; view8[1787]=0xa3;
view8[1788]=0x80; view8[1789]=0x8d; view8[1790]=0x9a; view8[1791]=0x97;
// Load the XtimeE lookup table
view8[1792]=0x00; view8[1793]=0x0e; view8[1794]=0x1c; view8[1795]=0x12; view8[1796]=0x38; view8[1797]=0x36;
view8[1798]=0x24; view8[1799]=0x2a; view8[1800]=0x70; view8[1801]=0x7e; view8[1802]=0x6c; view8[1803]=0x62;
view8[1804]=0x48; view8[1805]=0x46; view8[1806]=0x54; view8[1807]=0x5a; view8[1808]=0xe0; view8[1809]=0xee;
view8[1810]=0xfc; view8[1811]=0xf2; view8[1812]=0xd8; view8[1813]=0xd6; view8[1814]=0xc4; view8[1815]=0xca;
view8[1816]=0x90; view8[1817]=0x9e; view8[1818]=0x8c; view8[1819]=0x82; view8[1820]=0xa8; view8[1821]=0xa6;
view8[1822]=0xb4; view8[1823]=0xba; view8[1824]=0xdb; view8[1825]=0xd5; view8[1826]=0xc7; view8[1827]=0xc9;
view8[1828]=0xe3; view8[1829]=0xed; view8[1830]=0xff; view8[1831]=0xf1; view8[1832]=0xab; view8[1833]=0xa5;
view8[1834]=0xb7; view8[1835]=0xb9; view8[1836]=0x93; view8[1837]=0x9d; view8[1838]=0x8f; view8[1839]=0x81;
view8[1840]=0x3b; view8[1841]=0x35; view8[1842]=0x27; view8[1843]=0x29; view8[1844]=0x03; view8[1845]=0x0d;
view8[1846]=0x1f; view8[1847]=0x11; view8[1848]=0x4b; view8[1849]=0x45; view8[1850]=0x57; view8[1851]=0x59;
view8[1852]=0x73; view8[1853]=0x7d; view8[1854]=0x6f; view8[1855]=0x61; view8[1856]=0xad; view8[1857]=0xa3;
view8[1858]=0xb1; view8[1859]=0xbf; view8[1860]=0x95; view8[1861]=0x9b; view8[1862]=0x89; view8[1863]=0x87;
view8[1864]=0xdd; view8[1865]=0xd3; view8[1866]=0xc1; view8[1867]=0xcf; view8[1868]=0xe5; view8[1869]=0xeb;
view8[1870]=0xf9; view8[1871]=0xf7; view8[1872]=0x4d; view8[1873]=0x43; view8[1874]=0x51; view8[1875]=0x5f;
view8[1876]=0x75; view8[1877]=0x7b; view8[1878]=0x69; view8[1879]=0x67; view8[1880]=0x3d; view8[1881]=0x33;
view8[1882]=0x21; view8[1883]=0x2f; view8[1884]=0x05; view8[1885]=0x0b; view8[1886]=0x19; view8[1887]=0x17;
view8[1888]=0x76; view8[1889]=0x78; view8[1890]=0x6a; view8[1891]=0x64; view8[1892]=0x4e; view8[1893]=0x40;
view8[1894]=0x52; view8[1895]=0x5c; view8[1896]=0x06; view8[1897]=0x08; view8[1898]=0x1a; view8[1899]=0x14;
view8[1900]=0x3e; view8[1901]=0x30; view8[1902]=0x22; view8[1903]=0x2c; view8[1904]=0x96; view8[1905]=0x98;
view8[1906]=0x8a; view8[1907]=0x84; view8[1908]=0xae; view8[1909]=0xa0; view8[1910]=0xb2; view8[1911]=0xbc;
view8[1912]=0xe6; view8[1913]=0xe8; view8[1914]=0xfa; view8[1915]=0xf4; view8[1916]=0xde; view8[1917]=0xd0;
view8[1918]=0xc2; view8[1919]=0xcc; view8[1920]=0x41; view8[1921]=0x4f; view8[1922]=0x5d; view8[1923]=0x53;
view8[1924]=0x79; view8[1925]=0x77; view8[1926]=0x65; view8[1927]=0x6b; view8[1928]=0x31; view8[1929]=0x3f;
view8[1930]=0x2d; view8[1931]=0x23; view8[1932]=0x09; view8[1933]=0x07; view8[1934]=0x15; view8[1935]=0x1b;
view8[1936]=0xa1; view8[1937]=0xaf; view8[1938]=0xbd; view8[1939]=0xb3; view8[1940]=0x99; view8[1941]=0x97;
view8[1942]=0x85; view8[1943]=0x8b; view8[1944]=0xd1; view8[1945]=0xdf; view8[1946]=0xcd; view8[1947]=0xc3;
view8[1948]=0xe9; view8[1949]=0xe7; view8[1950]=0xf5; view8[1951]=0xfb; view8[1952]=0x9a; view8[1953]=0x94;
view8[1954]=0x86; view8[1955]=0x88; view8[1956]=0xa2; view8[1957]=0xac; view8[1958]=0xbe; view8[1959]=0xb0;
view8[1960]=0xea; view8[1961]=0xe4; view8[1962]=0xf6; view8[1963]=0xf8; view8[1964]=0xd2; view8[1965]=0xdc;
view8[1966]=0xce; view8[1967]=0xc0; view8[1968]=0x7a; view8[1969]=0x74; view8[1970]=0x66; view8[1971]=0x68;
view8[1972]=0x42; view8[1973]=0x4c; view8[1974]=0x5e; view8[1975]=0x50; view8[1976]=0x0a; view8[1977]=0x04;
view8[1978]=0x16; view8[1979]=0x18; view8[1980]=0x32; view8[1981]=0x3c; view8[1982]=0x2e; view8[1983]=0x20;
view8[1984]=0xec; view8[1985]=0xe2; view8[1986]=0xf0; view8[1987]=0xfe; view8[1988]=0xd4; view8[1989]=0xda;
view8[1990]=0xc8; view8[1991]=0xc6; view8[1992]=0x9c; view8[1993]=0x92; view8[1994]=0x80; view8[1995]=0x8e;
view8[1996]=0xa4; view8[1997]=0xaa; view8[1998]=0xb8; view8[1999]=0xb6; view8[2000]=0x0c; view8[2001]=0x02;
view8[2002]=0x10; view8[2003]=0x1e; view8[2004]=0x34; view8[2005]=0x3a; view8[2006]=0x28; view8[2007]=0x26;
view8[2008]=0x7c; view8[2009]=0x72; view8[2010]=0x60; view8[2011]=0x6e; view8[2012]=0x44; view8[2013]=0x4a;
view8[2014]=0x58; view8[2015]=0x56; view8[2016]=0x37; view8[2017]=0x39; view8[2018]=0x2b; view8[2019]=0x25;
view8[2020]=0x0f; view8[2021]=0x01; view8[2022]=0x13; view8[2023]=0x1d; view8[2024]=0x47; view8[2025]=0x49;
view8[2026]=0x5b; view8[2027]=0x55; view8[2028]=0x7f; view8[2029]=0x71; view8[2030]=0x63; view8[2031]=0x6d;
view8[2032]=0xd7; view8[2033]=0xd9; view8[2034]=0xcb; view8[2035]=0xc5; view8[2036]=0xef; view8[2037]=0xe1;
view8[2038]=0xf3; view8[2039]=0xfd; view8[2040]=0xa7; view8[2041]=0xa9; view8[2042]=0xbb; view8[2043]=0xb5;
view8[2044]=0x9f; view8[2045]=0x91; view8[2046]=0x83; view8[2047]=0x8d;
// Load the rcon lookup table
view8[2048]=0x00; view8[2049]=0x01; view8[2050]=0x02; view8[2051]=0x04; view8[2052]=0x08; view8[2053]=0x10;
view8[2054]=0x20; view8[2055]=0x40; view8[2056]=0x80; view8[2057]=0x1B; view8[2058]=0x36;
		}

		/**
		 * @param {int} dest Byte-pointer to the destination memory.
		 * @param {int} src Byte-pointer to the source memory.
		 * @param {int} len Number of bytes to copy.
		 */
		function copy(dest, src, len) {
			dest = dest|0;
			src = src|0;
			len = len|0;
			for(len = (len - 1)|0 ; (len|0) >= 0 ; len = (len - 1)|0) {
				view8[(dest + len)|0] = view8[(src + len)|0];
			}
		}

		/**
		 * @param {int} state Byte-pointer to the state array.
		 */
		function shiftRows(state) {
			state = state|0;
			var tmp = 0;

			// just substitue row 0
			view8[(state     )|0] = view8[(Sbox + (view8[(state     )|0]|0))|0];
			view8[(state +  4)|0] = view8[(Sbox + (view8[(state +  4)|0]|0))|0];
			view8[(state +  8)|0] = view8[(Sbox + (view8[(state +  8)|0]|0))|0];
			view8[(state + 12)|0] = view8[(Sbox + (view8[(state + 12)|0]|0))|0];

			// rotate row 1
			tmp                   = view8[(Sbox + (view8[(state +  1)|0]|0))|0]|0;
			view8[(state +  1)|0] = view8[(Sbox + (view8[(state +  5)|0]|0))|0];
			view8[(state +  5)|0] = view8[(Sbox + (view8[(state +  9)|0]|0))|0];
			view8[(state +  9)|0] = view8[(Sbox + (view8[(state + 13)|0]|0))|0];
			view8[(state + 13)|0] = tmp;

			// rotate row 2
			tmp                   = view8[(Sbox + (view8[(state +  2)|0]|0))|0]|0;
			view8[(state +  2)|0] = view8[(Sbox + (view8[(state + 10)|0]|0))|0];
			view8[(state + 10)|0] = tmp;
			tmp                   = view8[(Sbox + (view8[(state +  6)|0]|0))|0]|0;
			view8[(state +  6)|0] = view8[(Sbox + (view8[(state + 14)|0]|0))|0];
			view8[(state + 14)|0] = tmp;

			// rotate row 3
			tmp                   = view8[(Sbox + (view8[(state + 15)|0]|0))|0]|0;
			view8[(state + 15)|0] = view8[(Sbox + (view8[(state + 11)|0]|0))|0];
			view8[(state + 11)|0] = view8[(Sbox + (view8[(state +  7)|0]|0))|0];
			view8[(state +  7)|0] = view8[(Sbox + (view8[(state +  3)|0]|0))|0];
			view8[(state +  3)|0] = tmp;

		}

		/**
		 * @param {int} state Byte-pointer to the state array.
		 */
		function invShiftRows(state) {
			state = state|0;
			var tmp = 0;

			// restore row 0
			view8[(state     )|0] = view8[(InvSbox + (view8[(state     )|0]|0))|0];
			view8[(state +  4)|0] = view8[(InvSbox + (view8[(state +  4)|0]|0))|0];
			view8[(state +  8)|0] = view8[(InvSbox + (view8[(state +  8)|0]|0))|0];
			view8[(state + 12)|0] = view8[(InvSbox + (view8[(state + 12)|0]|0))|0];

			// restore row 1
			tmp                   = view8[(InvSbox + (view8[(state + 13)|0]|0))|0]|0;
			view8[(state + 13)|0] = view8[(InvSbox + (view8[(state +  9)|0]|0))|0];
			view8[(state +  9)|0] = view8[(InvSbox + (view8[(state +  5)|0]|0))|0];
			view8[(state +  5)|0] = view8[(InvSbox + (view8[(state +  1)|0]|0))|0];
			view8[(state +  1)|0] = tmp;

			// restore row 2
			tmp                   = view8[(InvSbox + (view8[(state +  2)|0]|0))|0]|0;
			view8[(state +  2)|0] = view8[(InvSbox + (view8[(state + 10)|0]|0))|0];
			view8[(state + 10)|0] = tmp;
			tmp                   = view8[(InvSbox + (view8[(state +  6)|0]|0))|0]|0;
			view8[(state +  6)|0] = view8[(InvSbox + (view8[(state + 14)|0]|0))|0];
			view8[(state + 14)|0] = tmp;

			// restore row 3
			tmp                   = view8[(InvSbox + (view8[(state +  3)|0]|0))|0]|0;
			view8[(state +  3)|0] = view8[(InvSbox + (view8[(state +  7)|0]|0))|0];
			view8[(state +  7)|0] = view8[(InvSbox + (view8[(state + 11)|0]|0))|0];
			view8[(state + 11)|0] = view8[(InvSbox + (view8[(state + 15)|0]|0))|0];
			view8[(state + 15)|0] = tmp;
		}

		/**
		 * @param {int} state Byte-pointer to the state array.
		 */
		function mixSubColumn(state) {
			state = state|0;

			// mix column 0
			view8[(temp +  0)|0] =
				view8[(Xtime2Sbox + (view8[(state +  0)|0]|0))|0] ^
				view8[(Xtime3Sbox + (view8[(state +  5)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state + 10)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state + 15)|0]|0))|0];
			view8[(temp +  1)|0] =
				view8[(Sbox       + (view8[(state +  0)|0]|0))|0] ^
				view8[(Xtime2Sbox + (view8[(state +  5)|0]|0))|0] ^
				view8[(Xtime3Sbox + (view8[(state + 10)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state + 15)|0]|0))|0];
			view8[(temp +  2)|0] =
				view8[(Sbox       + (view8[(state +  0)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  5)|0]|0))|0] ^
				view8[(Xtime2Sbox + (view8[(state + 10)|0]|0))|0] ^
				view8[(Xtime3Sbox + (view8[(state + 15)|0]|0))|0];
			view8[(temp +  3)|0] =
				view8[(Xtime3Sbox + (view8[(state +  0)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  5)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state + 10)|0]|0))|0] ^
				view8[(Xtime2Sbox + (view8[(state + 15)|0]|0))|0];

			// mix column 1
			view8[(temp +  4)|0] =
				view8[(Xtime2Sbox + (view8[(state +  4)|0]|0))|0] ^
				view8[(Xtime3Sbox + (view8[(state +  9)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state + 14)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  3)|0]|0))|0];
			view8[(temp +  5)|0] =
				view8[(Sbox       + (view8[(state +  4)|0]|0))|0] ^
				view8[(Xtime2Sbox + (view8[(state +  9)|0]|0))|0] ^
				view8[(Xtime3Sbox + (view8[(state + 14)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  3)|0]|0))|0];
			view8[(temp +  6)|0] =
				view8[(Sbox       + (view8[(state +  4)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  9)|0]|0))|0] ^
				view8[(Xtime2Sbox + (view8[(state + 14)|0]|0))|0] ^
				view8[(Xtime3Sbox + (view8[(state +  3)|0]|0))|0];
			view8[(temp +  7)|0] =
				view8[(Xtime3Sbox + (view8[(state +  4)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  9)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state + 14)|0]|0))|0] ^
				view8[(Xtime2Sbox + (view8[(state +  3)|0]|0))|0];

			// mix column 2
			view8[(temp +  8)|0] =
				view8[(Xtime2Sbox + (view8[(state +  8)|0]|0))|0] ^
				view8[(Xtime3Sbox + (view8[(state + 13)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  2)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  7)|0]|0))|0];
			view8[(temp +  9)|0] =
				view8[(Sbox       + (view8[(state +  8)|0]|0))|0] ^
				view8[(Xtime2Sbox + (view8[(state + 13)|0]|0))|0] ^
				view8[(Xtime3Sbox + (view8[(state +  2)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  7)|0]|0))|0];
			view8[(temp + 10)|0] =
				view8[(Sbox       + (view8[(state +  8)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state + 13)|0]|0))|0] ^
				view8[(Xtime2Sbox + (view8[(state +  2)|0]|0))|0] ^
				view8[(Xtime3Sbox + (view8[(state +  7)|0]|0))|0];
			view8[(temp + 11)|0] =
				view8[(Xtime3Sbox + (view8[(state +  8)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state + 13)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  2)|0]|0))|0] ^
				view8[(Xtime2Sbox + (view8[(state +  7)|0]|0))|0];

			// mix column 3
			view8[(temp + 12)|0] =
				view8[(Xtime2Sbox + (view8[(state + 12)|0]|0))|0] ^
				view8[(Xtime3Sbox + (view8[(state +  1)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  6)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state + 11)|0]|0))|0];
			view8[(temp + 13)|0] =
				view8[(Sbox       + (view8[(state + 12)|0]|0))|0] ^
				view8[(Xtime2Sbox + (view8[(state +  1)|0]|0))|0] ^
				view8[(Xtime3Sbox + (view8[(state +  6)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state + 11)|0]|0))|0];
			view8[(temp + 14)|0] =
				view8[(Sbox       + (view8[(state + 12)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  1)|0]|0))|0] ^
				view8[(Xtime2Sbox + (view8[(state +  6)|0]|0))|0] ^
				view8[(Xtime3Sbox + (view8[(state + 11)|0]|0))|0];
			view8[(temp + 15)|0] =
				view8[(Xtime3Sbox + (view8[(state + 12)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  1)|0]|0))|0] ^
				view8[(Sbox       + (view8[(state +  6)|0]|0))|0] ^
				view8[(Xtime2Sbox + (view8[(state + 11)|0]|0))|0];

			// store to state
			copy(state, temp, 16);
		}

		function invMixSubColumns(state) {
			state = state|0;
			var i = 0;

			// restore column 0
			view8[(temp +  0)|0] =
				view8[(XtimeE + (view8[(state +  0)|0]|0))|0] ^
				view8[(XtimeB + (view8[(state +  1)|0]|0))|0] ^
				view8[(XtimeD + (view8[(state +  2)|0]|0))|0] ^
				view8[(Xtime9 + (view8[(state +  3)|0]|0))|0];
			view8[(temp +  5)|0] =
				view8[(Xtime9 + (view8[(state +  0)|0]|0))|0] ^
				view8[(XtimeE + (view8[(state +  1)|0]|0))|0] ^
				view8[(XtimeB + (view8[(state +  2)|0]|0))|0] ^
				view8[(XtimeD + (view8[(state +  3)|0]|0))|0];
			view8[(temp + 10)|0] =
				view8[(XtimeD + (view8[(state +  0)|0]|0))|0] ^
				view8[(Xtime9 + (view8[(state +  1)|0]|0))|0] ^
				view8[(XtimeE + (view8[(state +  2)|0]|0))|0] ^
				view8[(XtimeB + (view8[(state +  3)|0]|0))|0];
			view8[(temp + 15)|0] =
				view8[(XtimeB + (view8[(state +  0)|0]|0))|0] ^
				view8[(XtimeD + (view8[(state +  1)|0]|0))|0] ^
				view8[(Xtime9 + (view8[(state +  2)|0]|0))|0] ^
				view8[(XtimeE + (view8[(state +  3)|0]|0))|0];

			// restore column 1
			view8[(temp +  4)|0] =
				view8[(XtimeE + (view8[(state +  4)|0]|0))|0] ^
				view8[(XtimeB + (view8[(state +  5)|0]|0))|0] ^
				view8[(XtimeD + (view8[(state +  6)|0]|0))|0] ^
				view8[(Xtime9 + (view8[(state +  7)|0]|0))|0];
			view8[(temp +  9)|0] =
				view8[(Xtime9 + (view8[(state +  4)|0]|0))|0] ^
				view8[(XtimeE + (view8[(state +  5)|0]|0))|0] ^
				view8[(XtimeB + (view8[(state +  6)|0]|0))|0] ^
				view8[(XtimeD + (view8[(state +  7)|0]|0))|0];
			view8[(temp + 14)|0] =
				view8[(XtimeD + (view8[(state +  4)|0]|0))|0] ^
				view8[(Xtime9 + (view8[(state +  5)|0]|0))|0] ^
				view8[(XtimeE + (view8[(state +  6)|0]|0))|0] ^
				view8[(XtimeB + (view8[(state +  7)|0]|0))|0];
			view8[(temp +  3)|0] =
				view8[(XtimeB + (view8[(state +  4)|0]|0))|0] ^
				view8[(XtimeD + (view8[(state +  5)|0]|0))|0] ^
				view8[(Xtime9 + (view8[(state +  6)|0]|0))|0] ^
				view8[(XtimeE + (view8[(state +  7)|0]|0))|0];

			// restore column 2
			view8[(temp +  8)|0] =
				view8[(XtimeE + (view8[(state +  8)|0]|0))|0] ^
				view8[(XtimeB + (view8[(state +  9)|0]|0))|0] ^
				view8[(XtimeD + (view8[(state + 10)|0]|0))|0] ^
				view8[(Xtime9 + (view8[(state + 11)|0]|0))|0];
			view8[(temp + 13)|0] =
				view8[(Xtime9 + (view8[(state +  8)|0]|0))|0] ^
				view8[(XtimeE + (view8[(state +  9)|0]|0))|0] ^
				view8[(XtimeB + (view8[(state + 10)|0]|0))|0] ^
				view8[(XtimeD + (view8[(state + 11)|0]|0))|0];
			view8[(temp +  2)|0] =
				view8[(XtimeD + (view8[(state +  8)|0]|0))|0] ^
				view8[(Xtime9 + (view8[(state +  9)|0]|0))|0] ^
				view8[(XtimeE + (view8[(state + 10)|0]|0))|0] ^
				view8[(XtimeB + (view8[(state + 11)|0]|0))|0];
			view8[(temp +  7)|0] =
				view8[(XtimeB + (view8[(state +  8)|0]|0))|0] ^
				view8[(XtimeD + (view8[(state +  9)|0]|0))|0] ^
				view8[(Xtime9 + (view8[(state + 10)|0]|0))|0] ^
				view8[(XtimeE + (view8[(state + 11)|0]|0))|0];

			// restore column 3
			view8[(temp + 12)|0] =
				view8[(XtimeE + (view8[(state + 12)|0]|0))|0] ^
				view8[(XtimeB + (view8[(state + 13)|0]|0))|0] ^
				view8[(XtimeD + (view8[(state + 14)|0]|0))|0] ^
				view8[(Xtime9 + (view8[(state + 15)|0]|0))|0];
			view8[(temp +  1)|0] =
				view8[(Xtime9 + (view8[(state + 12)|0]|0))|0] ^
				view8[(XtimeE + (view8[(state + 13)|0]|0))|0] ^
				view8[(XtimeB + (view8[(state + 14)|0]|0))|0] ^
				view8[(XtimeD + (view8[(state + 15)|0]|0))|0];
			view8[(temp +  6)|0] =
				view8[(XtimeD + (view8[(state + 12)|0]|0))|0] ^
				view8[(Xtime9 + (view8[(state + 13)|0]|0))|0] ^
				view8[(XtimeE + (view8[(state + 14)|0]|0))|0] ^
				view8[(XtimeB + (view8[(state + 15)|0]|0))|0];
			view8[(temp + 11)|0] =
				view8[(XtimeB + (view8[(state + 12)|0]|0))|0] ^
				view8[(XtimeD + (view8[(state + 13)|0]|0))|0] ^
				view8[(Xtime9 + (view8[(state + 14)|0]|0))|0] ^
				view8[(XtimeE + (view8[(state + 15)|0]|0))|0];

			for( ; (i|0) < 16 ; i = (i + 1)|0 )
				view8[(state + i)|0] = view8[(InvSbox + (view8[(temp + i)|0]|0))|0];
		}

		/**
		 * @param {int} state Byte-pointer to the state array.
		 * @param {int} key Byte-pointer to the key.
		 */
		function addRoundKey(state, key) {
			state = state|0;
			key = key|0;
			var i = 0;
			for(i = 0 ; (i|0) < 16 ; i = (i + 1)|0) {
				view8[(state + i)|0] = view8[(state + i)|0] ^ view8[(key + i)|0];
			}
		}

		/**
		 * @param {int} rk Byte-pointer to the expanded key
		 * @param {int} key Byte-pointer to the key
		 * @param {int} [keysize] Number of bits in the key.
		 *                        Possible values are 128, 192, and 256.
		 *                        Default is 128.
		 * @return {int} Number of rounds for the keysize
		 */
		function expandKey(rk, key, keysize) {
			rk = rk|0;
			key = key|0;
			keysize = keysize|0;
			var i = 0, nRounds = 0, keyColumns = 0, tmp0 = 0, tmp1 = 0, tmp2 = 0, tmp3 = 0, tmp4 = 0;
			switch(keysize|0) {
				case 256:
					nRounds = 14;
					keyColumns = 8;
					break;
				case 192:
					nRounds = 12;
					keyColumns = 6;
					break;
				default: // 128
					nRounds = 10;
					keyColumns = 4;
			}

			// start off the rk with the key
			copy(rk, key, (keyColumns * 4));

			for(i = keyColumns; (i|0) < (((nRounds + 1)|0) * 4) ; i = (i + 1)|0) {
				tmp0 = view8[(rk + (4 * i - 4))|0]|0;
				tmp1 = view8[(rk + (4 * i - 3))|0]|0;
				tmp2 = view8[(rk + (4 * i - 2))|0]|0;
				tmp3 = view8[(rk + (4 * i - 1))|0]|0;

				if((((i|0) % (keyColumns|0))|0) == 0) {
					tmp4 = tmp3;
					tmp3 = view8[(Sbox + tmp0)|0]|0;
					tmp0 = view8[(Sbox + tmp1)|0] ^
						   view8[(rcon + (((i|0) / (keyColumns|0))|0))|0];
					tmp1 = view8[(Sbox + tmp2)|0]|0;
					tmp2 = view8[(Sbox + tmp4)|0]|0;
				} else if((((keyColumns|0) > 6) & ((((i|0) % (keyColumns|0))|0) == 4)) != 0) {
					tmp0 = view8[(Sbox + tmp0)|0]|0;
					tmp1 = view8[(Sbox + tmp1)|0]|0;
					tmp2 = view8[(Sbox + tmp2)|0]|0;
					tmp3 = view8[(Sbox + tmp3)|0]|0;
				}

				view8[(rk + (4 * i + 0))|0] = view8[(rk + (4 * i - 4 * keyColumns + 0))|0] ^ tmp0;
				view8[(rk + (4 * i + 1))|0] = view8[(rk + (4 * i - 4 * keyColumns + 1))|0] ^ tmp1;
				view8[(rk + (4 * i + 2))|0] = view8[(rk + (4 * i - 4 * keyColumns + 2))|0] ^ tmp2;
				view8[(rk + (4 * i + 3))|0] = view8[(rk + (4 * i - 4 * keyColumns + 3))|0] ^ tmp3;
			}

			return (nRounds|0);
		}

		/**
		 * @param rk Byte-pointer to the expanded key.
		 * @param nRounds Number of rounds to perform on the state.
		 * @param plain Byte-pointer to the plaintext block.
		 * @param cipher Byte-pointer to the ciphertext block.
		 */
		function encrypt(rk, nRounds, plain, cipher) {
			rk = rk|0;
			nRounds = nRounds|0;
			plain = plain|0;
			cipher = cipher|0;
			var round = 0;

			copy(state, plain, 16);

			addRoundKey(state, rk);

			for(round = 1 ; (round|0) < ((nRounds + 1)|0) ; round = (round + 1)|0) {
				if((round|0) < (nRounds|0)) {
					mixSubColumn(state);
				} else {
					shiftRows(state);
				}
				addRoundKey(state, (rk + round * 16)|0);
			}

			copy(cipher, state, 16);
		}

		/**
		 * @param rk Byte-pointer to the expanded key.
		 * @param nRounds Number of rounds to perform on the state.
		 * @param cipher Byte-pointer to the ciphertext block.
		 * @param plain Byte-pointer to the plaintext block.
		 */
		function decrypt(rk, nRounds, cipher, plain) {
			rk = rk|0;
			nRounds = nRounds|0;
			cipher = cipher|0;
			plain = plain|0;
			var round = 0;

			copy(state, cipher, 16);

			addRoundKey(state, (rk + nRounds * 16)|0);
			invShiftRows(state);

			for(round = (nRounds - 1)|0 ; (round|0) >= 0 ; round = (round - 1)|0) {
				addRoundKey (state, (rk + (round * 16))|0);
				if((round|0) > 0)
					invMixSubColumns(state);
			}

			copy(plain, state, 16);
		}

		return {
			init: init,
			expandKey: expandKey,
			encrypt:encrypt,
			decrypt: decrypt
		}
	}

	var heapSize = 4096; // 2^12
	var rkOffset = 2092; // 240b
	var keyOffset = 2332; // 32b
	var plainOffset = 2364; // 16b
	var cipherOffset = 2380; // 16b

	var heap   = new ArrayBuffer(heapSize);
	var heap8  = new Uint8Array(heap);
	var heap16 = new Uint16Array(heap);
	var asm = aesAsm(window, null, heap);
	asm.init();

	/**
	 * @param {String} password
	 * @param {String} data
	 * @param {int} keysize
	 * @returns {ArrayBuffer}
	 */
	function encrypt(password, data, keysize) {
		keysize = keysize|0;
		var ciphertext, ciphertextLen, nRounds, padLen;
		var i, c, d, p;

		// Validate keysize
		if(keysize !== 128 && keysize !== 192 && keysize !== 256) {
			keysize = 128;
		}

		// TODO Create a real key from the password.
		for(i = 0 ; i < (keysize / 8) ; i++) {
			heap8[keyOffset + i] = 0;
		}
		nRounds = asm.expandKey(rkOffset, keyOffset, keysize);

		// Create the ciphertext buffer
		ciphertextLen = data.length * 2 + 1; // + 1 for the terminating 0x80
		ciphertextLen = ciphertextLen + (16 - (ciphertextLen % 16)) % 16;
		ciphertext = new ArrayBuffer(ciphertextLen);

		// Encrypt the data in 8-character blocks
		for(c = 0, d = 0, p = 0 ; d < data.length ; ) {
			heap16[(plainOffset >> 1) + p++] = data.charCodeAt(d++);
			if((p % 8) > 0) {
				continue;
			}

			asm.encrypt(rkOffset, nRounds, plainOffset, cipherOffset);
			CS.arrayBufferInToArrayBuffer(ciphertext, c, heap, cipherOffset, 16);
			c += 16;
			p = 0;
		}

		// Convert the plaintext pointer to a byte-pointer
		p = p << 1;

		// Calculate the need amount of padding
		padLen = 16 - (p % 16);

		// Append padding
		for(i = 0 ; i < padLen ; i++) {
			heap8[plainOffset + p++] = padLen;
		}

		// Encrypt padded block
		asm.encrypt(rkOffset, nRounds, plainOffset, cipherOffset);
		CS.arrayBufferInToArrayBuffer(ciphertext, c, heap, cipherOffset, 16);

		return ciphertext;
	}

	/**
	 * @param {String} password
	 * @param {ArrayBuffer} data
	 * @param {int} keysize
	 * @returns {string}
	 */
	function decrypt(password, data, keysize) {
		keysize = keysize|0;
		var data8 = new Uint8Array(data);
		var plaintext, nRounds;
		var i, c, d;

		// Validate keysize
		if(keysize !== 128 && keysize !== 192 && keysize !== 256) {
			keysize = 128;
		}

		// TODO Create a real key from the password.
		for(i = 0 ; i < (keysize / 8) ; i++) {
			heap8[keyOffset + i] = 0;//65 + i;
		}
		nRounds = asm.expandKey(rkOffset, keyOffset, keysize);

		// Create the plaintext buffer
		plaintext = "";

		// Decrypt the data in 16-byte blocks
		for(c = 0, d = 0 ; d < data8.length ; ) {
			heap8[cipherOffset + c++] = data8[d++];
			if((c % 16) > 0) {
				continue;
			}

			asm.decrypt(rkOffset, nRounds, cipherOffset, plainOffset);

			// Find the 0x80 byte and truncate
			// start at the end and search backwards
			i = plainOffset + 16;
			if(d === data8.length) {
				do {
					i--;
				} while(heap8[i] !== 0x80);
			}
			// Convert text up to the 0x80 byte
			for(c = plainOffset ; c < i ; c += 2) {
				plaintext += String.fromCharCode(heap8[c]);
			}
			c = 0;
		}

		return plaintext;
	}

	function testEncrypt(keysize) {
		keysize = keysize || 128;
		var i, j, nRounds;
		var keyView = new Uint8Array(heap, keyOffset, 32);
		var plainView = new Uint8Array(heap, plainOffset, 16);

		// set the key
		for(i = 0 ; i < (keysize / 8) ; i++) {
			keyView[i] = i;
		}
		console.log("KEY=" + arrayToHex(heap, keyOffset, (keysize / 8)));

		nRounds = asm.expandKey(rkOffset, keyOffset, keysize);
		for(i = 0 ; i < (16 * (nRounds + 1)) ; i += 16) {
			console.log("RK=" + arrayToHex(heap, rkOffset + i, 16));
		}

		// set plaintext
		for(i = 0 ; i < 16 ; i++) {
			plainView[i] = 16 * i + i;
		}
		console.log("PT=" + arrayToHex(heap, plainOffset, 16));

		asm.encrypt(rkOffset, nRounds, plainOffset, cipherOffset);
		console.log("CT=" + arrayToHex(heap, cipherOffset, 16));
	}

	function testDecrypt(keysize) {
		keysize = keysize || 128;
		var i, j, nRounds;
		var keyView = new Uint8Array(heap, keyOffset, 32);
		var plainView = new Uint8Array(heap, plainOffset, 16);

		// set the key
		for(i = 0 ; i < (keysize / 8) ; i++) {
			keyView[i] = i;
		}
		console.log("KEY=" + arrayToHex(heap, keyOffset, (keysize / 8)));

		nRounds = asm.expandKey(rkOffset, keyOffset, keysize);
		for(i = 0 ; i < (16 * (nRounds + 1)) ; i += 16) {
			console.log("RK=" + arrayToHex(heap, rkOffset + i, 16));
		}

		// set plaintext
		for(i = 0 ; i < 16 ; i++) {
			plainView[i] = 16 * i + i;
		}
		// encrypt for ciphertext
		asm.encrypt(rkOffset, nRounds, plainOffset, cipherOffset);
		console.log("CT=" + arrayToHex(heap, cipherOffset, 16));

		asm.decrypt(rkOffset, nRounds, cipherOffset, plainOffset);
		console.log("PT=" + arrayToHex(heap, plainOffset, 16));
	}

	return {
		"encrypt": encrypt,
		"decrypt": decrypt,
		"testEncrypt": testEncrypt,
		"testDecrypt": testDecrypt
	}

}();
