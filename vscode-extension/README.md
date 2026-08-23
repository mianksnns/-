# Ciphey Decode - VS Code Extension

Decode selected ciphertext using Ciphey's automatic decoding engine.

## Features

- **Decode Selection**: Select encoded text and decode it with a right-click
- **Decode and Replace**: Replace selected text with the decoded result
- **Show Decode Path**: View the sequence of decoders used

## Usage

1. Select encoded text in the editor
2. Right-click and choose "Ciphey: Decode Selection"
3. View the decoded result in a new panel

Or use the command palette (`Ctrl+Shift+P`):
- `Ciphey: Decode Selection`
- `Ciphey: Decode and Replace`
- `Ciphey: Show Decode Path`

## Configuration

- `ciphey.timeout`: Timeout in seconds for decode operations (default: 10)
- `ciphey.showPath`: Show the decoder path in results (default: true)
- `ciphey.regex`: Optional regex pattern to match against decoded text

## Requirements

- VS Code 1.80.0 or higher
- Ciphey WASM module (built separately)

## Building

```bash
npm install
npm run compile
```

## License

MIT
