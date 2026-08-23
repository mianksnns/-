import * as vscode from 'vscode';
import { decodeWithWasm, getWasmInfo, type WasmDecodeResult } from './wasmClient';

/**
 * Extension activation.
 */
export function activate(context: vscode.ExtensionContext) {
    console.log('Ciphey Decode extension is now active');

    // Register the decode command
    const decodeCommand = vscode.commands.registerCommand(
        'ciphey.decode',
        async () => {
            await decodeSelection(false);
        }
    );

    // Register the decode and replace command
    const decodeReplaceCommand = vscode.commands.registerCommand(
        'ciphey.decodeReplace',
        async () => {
            await decodeSelection(true);
        }
    );

    // Register the show path command
    const showPathCommand = vscode.commands.registerCommand(
        'ciphey.showPath',
        async () => {
            await showDecodePath();
        }
    );

    const showInfoCommand = vscode.commands.registerCommand(
        'ciphey.showInfo',
        async () => {
            try {
                const info = await getWasmInfo();
                vscode.window.showInformationMessage(
                    `${info.name} ${info.version}: ${info.supported_features.join(', ')}`
                );
            } catch (error) {
                vscode.window.showErrorMessage(
                    `Failed to load WASM module: ${error instanceof Error ? error.message : 'Unknown error'}`
                );
            }
        }
    );

    context.subscriptions.push(decodeCommand, decodeReplaceCommand, showPathCommand, showInfoCommand);
}

/**
 * Extension deactivation.
 */
export function deactivate() {}

/**
 * Decode the selected text.
 */
async function decodeSelection(replace: boolean): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor found');
        return;
    }

    const selection = editor.selection;
    const selectedText = editor.document.getText(selection);

    if (!selectedText) {
        vscode.window.showWarningMessage('No text selected');
        return;
    }

    // Get configuration
    const config = vscode.workspace.getConfiguration('ciphey');
    const timeout = config.get<number>('timeout', 10);
    const showPath = config.get<boolean>('showPath', true);

    // Show progress
    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: 'Decoding...',
            cancellable: true,
        },
        async (progress, token) => {
            progress.report({ message: 'Analyzing input...' });

            try {
                // Call the decoding function
                const result = await callDecoder(selectedText, timeout);

                if (token.isCancellationRequested) {
                    return;
                }

                if (result.success) {
                    progress.report({ message: 'Decoded successfully!' });

                    if (replace) {
                        // Replace the selected text with decoded result
                        await editor.edit((editBuilder) => {
                            editBuilder.replace(selection, result.text || '');
                        });
                        vscode.window.showInformationMessage(
                            `Decoded: ${result.text?.substring(0, 100) || ''}${(result.text?.length || 0) > 100 ? '...' : ''}`
                        );
                    } else {
                        // Show result in a new panel
                        const panel = vscode.window.createWebviewPanel(
                            'cipheyResult',
                            'Ciphey Decode Result',
                            vscode.ViewColumn.Beside,
                            {}
                        );

                        panel.webview.html = getResultHtml(result, showPath);
                    }
                } else {
                    vscode.window.showErrorMessage(
                        `Failed to decode: ${result.error || 'Unknown error'}`
                    );
                }
            } catch (error) {
                vscode.window.showErrorMessage(
                    `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
                );
            }
        }
    );
}

/**
 * Show the decode path for the selected text.
 */
async function showDecodePath(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor found');
        return;
    }

    const selection = editor.selection;
    const selectedText = editor.document.getText(selection);

    if (!selectedText) {
        vscode.window.showWarningMessage('No text selected');
        return;
    }

    const config = vscode.workspace.getConfiguration('ciphey');
    const timeout = config.get<number>('timeout', 10);

    try {
        const result = await callDecoder(selectedText, timeout);

        if (result.success && result.path && result.path.length > 0) {
            const pathStr = result.path.join(' → ');
            vscode.window.showInformationMessage(`Decode path: ${pathStr}`);
        } else if (result.success) {
            vscode.window.showInformationMessage('Input is already plaintext');
        } else {
            vscode.window.showErrorMessage('Failed to decode');
        }
    } catch (error) {
        vscode.window.showErrorMessage(
            `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
    }
}

/**
 * Decoder result interface.
 */
interface DecodeResult {
    success: boolean;
    text?: string;
    path?: string[];
    confidence?: number;
    error?: string;
}

/**
 * Call the decoder (placeholder for actual implementation).
 *
 * In production, this would call the WASM module or a CLI subprocess.
 */
async function callDecoder(input: string, timeout: number): Promise<DecodeResult> {
    try {
        const result: WasmDecodeResult = await decodeWithWasm(input);
        return {
            success: result.success,
            text: result.text ?? undefined,
            path: result.path,
            confidence: result.confidence,
            error: result.error ?? undefined,
        };
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Failed to load or execute WASM module',
        };
    }
}

/**
 * Generate HTML for the result panel.
 */
function getResultHtml(result: DecodeResult, showPath: boolean): string {
    const pathHtml = showPath && result.path && result.path.length > 0
        ? `<div class="path"><strong>Path:</strong> ${result.path.join(' → ')}</div>`
        : '';

    const confidenceHtml = result.confidence !== undefined
        ? `<div class="confidence"><strong>Confidence:</strong> ${result.confidence}%</div>`
        : '';

    return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ciphey Decode Result</title>
    <style>
        body { font-family: var(--vscode-font-family); padding: 20px; }
        .result { margin: 10px 0; }
        .path { color: var(--vscode-descriptionForeground); margin-top: 10px; }
        .confidence { color: var(--vscode-descriptionForeground); }
        pre {
            background: var(--vscode-textCodeBlock-background);
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <h2>Decode Result</h2>
    <div class="result">
        <pre>${result.text || 'No result'}</pre>
    </div>
    ${pathHtml}
    ${confidenceHtml}
</body>
</html>`;
}
