/**
 * The didcomm bundler build, seen through wrangler's eyes: a .wasm import is
 * a compiled-but-uninstantiated WebAssembly.Module, and the glue JS ships no
 * declarations of its own (the package's index.d.ts describes index.js, which
 * we bypass — see didcomm-wasm.ts).
 */
declare module "didcomm/index_bg.wasm" {
  const wasmModule: WebAssembly.Module;
  export default wasmModule;
}

declare module "didcomm/index_bg.js";
