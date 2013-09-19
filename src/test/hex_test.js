/**
 * User: csteinhoff
 * Date: 9/19/13
 */

var assert = require("assert");

global["window"] = global;
require("../main/hex.js");

var result;

result = byteToHex(0);
assert.strictEqual(result, "00");
result = byteToHex(255);
assert.strictEqual(result, "ff");

result = shortToHex(0);
assert.strictEqual(result, "0000");
result = shortToHex(65535);
assert.strictEqual(result, "ffff");

result = wordToHex(0);
assert.strictEqual(result, "00000000");
result = wordToHex(4294967295);
assert.strictEqual(result, "ffffffff");

var array = new Uint8Array(32);
for(var i = 0 ; i < 32 ; i++) {
	array[i] = i;
}
result = arrayToHex(array);
assert.strictEqual(result, "000102030405060708090a0b0c0d0e0f" +
                           "101112131415161718191a1b1c1d1e1f");

result = intFromHex("00");
assert.strictEqual(result, 0);
result = intFromHex("ff");
assert.strictEqual(result, 255);
result = intFromHex("ffff");
assert.strictEqual(result, 65535);
result = intFromHex("7fffffff");
assert.strictEqual(result, 2147483647);
result = intFromHex("ffffffff");
assert.strictEqual(result, -1);
result = intFromHex("ffffff00");
assert.strictEqual(result, -256);

result = new Uint8Array(arrayFromHex("000102030405060708090a0b0c0d0e0f" +
                                     "101112131415161718191a1b1c1d1e1f"));
assert.strictEqual(result.byteLength, 32);
for(i = 0 ; i < 32 ; i++) {
	assert.strictEqual(result[i], i);
}

console.log("Passed");
