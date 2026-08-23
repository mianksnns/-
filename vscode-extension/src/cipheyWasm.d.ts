declare module '../pkg/ciphey_wasm.js' {
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

    export default function init(): Promise<void>;
    export function wasm_init(): void;
    export function wasm_decode(input: string): WasmDecodeResult;
    export function wasm_get_info(): WasmInfo;
}
