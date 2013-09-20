/**
 * User: csteinhoff
 * Date: 9/20/13
 */

function EntropyPool(size, fill) {
	size = size || 1024;
	fill = fill || 0;
	var array = new Array(size);
	var w = 0;
	var r = 0;

	// Initialize pool
	for(var f = 0 ; f < size ; f++) {
		array[f] = fill;
	}

	function plusOne(i) {
		return (i === size ? 0 : (i + 1));
	}

	function minusOne(i) {
		return (i === 0 ? size : (i - 1));
	}

	function product() {
		if(arguments.length === 0) {
			return 0;
		}
		var p = arguments[0];
		for(var i = 1 ; i < arguments.length ; i++) {
			p *= arguments[i];
		}
		return p;
	}

	array.addEntropy = function() {
//		console.log(JSON.stringify(arguments));
		array[w] = (
			(product.apply(null, arguments) * 1046527) ^
			(array[minusOne(w)])
		) & 0xffffffff;
		w = plusOne(w);
	};

	array.readEntropy = function() {
		var i = r;
		r = plusOne(r);
		return array[i];
	};

	return array;
}

