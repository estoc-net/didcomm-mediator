/**
 * The `@estoc/didcomm` package for workerd, standing in for
 * `@estoc/didcomm-node` (see the `alias` entry in wrangler.jsonc — the two
 * builds expose the identical wasm-bindgen API, so the rest of the codebase
 * imports the Node build and never knows).
 *
 * The package's own index.js is webpack-shaped: it imports the .wasm
 * expecting the bundler to instantiate it with the glue module's imports
 * wired up. Wrangler instead hands a .wasm import over as an uninstantiated
 * WebAssembly.Module, so this file does the wiring itself: every import the
 * module declares comes from "./index_bg.js", which is exactly the glue
 * module — instantiate with it, hand the exports back via __wbg_set_wasm
 * and run the module's start function, as the package's index.js would.
 */
import wasmModule from "@estoc/didcomm/index_bg.wasm";
import * as glue from "@estoc/didcomm/index_bg.js";

const instance = new WebAssembly.Instance(wasmModule, {
  "./index_bg.js": glue as unknown as Record<string, WebAssembly.ImportValue>,
});

(glue as { __wbg_set_wasm(exports: unknown): void }).__wbg_set_wasm(
  instance.exports
);
(instance.exports as { __wbindgen_start(): void }).__wbindgen_start();

export * from "@estoc/didcomm/index_bg.js";
