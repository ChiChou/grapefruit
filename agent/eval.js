[Int8Array, Int16Array, Int32Array, Uint8Array,
  Uint16Array, Uint32Array, Uint8ClampedArray,
  Float32Array, Float64Array].forEach(function (clazz) {
    clazz.prototype.toJSON = function () {
      return hexdump(new ArrayBuffer(this))
    }
  })

ArrayBuffer.prototype.toJSON = function() {
  return hexdump(this)
}

rpc.exports.eval = function (js) {
  ['log', 'warn', 'error', 'warning', 'info'].forEach(function (level) {
    console[level] = function () {
      send({
        subject: 'console.message',
        level: level,
        args: [].slice.call(arguments)
      });
    };
  });

  try {
    const result = (1, eval)(js);
    if (result instanceof ObjC.Object) {
      return ['string', result.toString()];
    } else if (result instanceof ArrayBuffer) {
      return result;
    } else {
      var type = (result === null) ? 'null' : typeof result;
      return [type, result];
    }
  } catch (e) {
    return ['error', e instanceof Error ? {
      name: e.name,
      message: e.message,
      stack: e.stack
    } : e + ''];
  }
}