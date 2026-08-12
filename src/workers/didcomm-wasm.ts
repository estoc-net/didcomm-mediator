/**
 * The `didcomm` package for workerd, standing in for `didcomm-node` (see the
 * `alias` entry in wrangler.jsonc — the two builds expose the identical
 * wasm-bindgen API, so the rest of the codebase imports didcomm-node and
 * never knows).
 *
 * The package's own index.js is webpack-shaped: it imports the .wasm
 * expecting the bundler to instantiate it with the glue module's imports
 * wired up. Wrangler instead hands a .wasm import over as an uninstantiated
 * WebAssembly.Module, so this file does the wiring itself: every import the
 * module declares comes from "./index_bg.js", which is exactly the glue
 * module — instantiate with it, hand the exports back via __wbg_set_wasm,
 * done.
 */
import wasmModule from "didcomm/index_bg.wasm";
import * as glue from "didcomm/index_bg.js";

const instance = new WebAssembly.Instance(wasmModule, {
  "./index_bg.js": glue as unknown as Record<string, WebAssembly.ImportValue>,
});

(glue as { __wbg_set_wasm(exports: unknown): void }).__wbg_set_wasm(
  instance.exports
);

export * from "didcomm/index_bg.js";
