export interface WasmDecodeResult {
    success: boolean;
    text: string | null;
    path: string[];
    confidence: number;
    error: string | null;
}

export interface WasmInfo {
    version: string;
    name: string;
    description: string;
    supported_features: string[];
}

type CipheyWasmModule = {
    default: () => Promise<void>;
    wasm_init: () => void;
    wasm_decode: (input: string) => WasmDecodeResult;
    wasm_get_info: () => WasmInfo;
};

let modulePromise: Promise<CipheyWasmModule> | null = null;

async function loadModule(): Promise<CipheyWasmModule> {
    if (!modulePromise) {
        modulePromise = import('../pkg/ciphey_wasm.js') as Promise<CipheyWasmModule>;
    }
    return modulePromise;
}

export async function decodeWithWasm(input: string): Promise<WasmDecodeResult> {
    const mod = await loadModule();
    await mod.default();
    mod.wasm_init();
    return mod.wasm_decode(input);
}

export async function getWasmInfo(): Promise<WasmInfo> {
    const mod = await loadModule();
    await mod.default();
    return mod.wasm_get_info();
}
