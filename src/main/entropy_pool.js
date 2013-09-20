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
	if(window.localStorage.getItem("entropy") === null) {
		for(var f = 0 ; f < size ; f++) {
			array[f] = (f & 0xff);
		}
	} else {
		loadEntropy();
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

	function persistEntropy() {
		var hex = "";
		for(var i = 0 ; i < size ; i++) {
			hex += byteToHex(array[i]);
		}
		window.localStorage.setItem("entropy", hex);
	}

	function loadEntropy() {
		var hex = window.localStorage.getItem("entropy");
		for(var i = 0, j = 0 ; (i < size) && ((j + 2) < hex.length) ; i++, j += 2) {
			array[i] = intFromHex(hex.substring(j, (j + 2)));
		}
	}

	setInterval(persistEntropy, 5000);

	window.document.addEventListener("mousemove", function(event) {
		array.addEntropy(event.screenX, event.screenY);
	});

	window["entropy"] = array;

}(window)
);

