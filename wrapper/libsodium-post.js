    if (typeof(process) === 'object' && typeof(process.removeAllListeners) === 'function') {
      process.removeAllListeners('uncaughtException');
      process.removeAllListeners('unhandledRejection');
    }
    return Module;
}

if (typeof define === 'function' && define.amd) {
    define(['exports'], expose_libsodium);
} else if (typeof exports === 'object' && typeof exports.nodeName !== 'string') {
    expose_libsodium(exports);
} else if (root) {
    root.libsodium = expose_libsodium(root.libsodium_mod || (root.commonJsStrict = {}));
} else if (denoroot) {
  denoroot.libsodium = expose_libsodium(denoroot.libsodium_mod || (denoroot.commonJsStrict = {}));
}

})(null, __denoroot, __document);
