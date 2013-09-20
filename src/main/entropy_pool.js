/**
 * User: csteinhoff
 * Date: 9/20/13
 */

"use strict";

(function(window) {

	var size = 4096;
	var array = new Array(size);
	var w = 0;
	var r = 0;

	// Initialize pool
	for(var f = 0 ; f < size ; f++) {
		array[f] = (f & 0xff);
	}

	function plusOne(i) {
		return (i === size ? 0 : (i + 1));
	}

	function minusOne(i) {
		return (i === 0 ? size : (i - 1));
	}

	array.addEntropy = function() {
		for(var i = 0 ; i < arguments.length ; i++, w = plusOne(w)) {
			array[w] = (array[minusOne(w)] ^ (arguments[i] & 0xff));
		}
	};

	array.readEntropy = function() {
		var i = r;
		r = plusOne(r);
		return array[i];
	};

	window.document.addEventListener("mousemove", function(event) {
		array.addEntropy(event.screenX, event.screenY);
	});

	window["entropy"] = array;

}(window)
);

