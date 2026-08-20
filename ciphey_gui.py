#!/usr/bin/env python3
"""ciphey_gui.py - Simple Tkinter GUI for the ciphey decoding tool.

Run:
    python3 ciphey_gui.py
"""

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from ciphey_api import ciphey_decrypt


class CipheyGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Ciphey Decoder")
        self.root.geometry("640x480")
        self.root.minsize(480, 360)

        self.result_queue: queue.Queue = queue.Queue()

        self._build_widgets()

    def _build_widgets(self) -> None:
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        # Ciphertext input
        ttk.Label(main, text="Ciphertext:").pack(anchor=tk.W)
        self.input_text = tk.Text(main, height=6, wrap=tk.WORD)
        self.input_text.pack(fill=tk.X, pady=(4, 8))

        # Buttons row
        buttons = ttk.Frame(main)
        buttons.pack(fill=tk.X, pady=(0, 8))
        self.decode_btn = ttk.Button(buttons, text="Decrypt", command=self.on_decrypt)
        self.decode_btn.pack(side=tk.LEFT)
        self.clear_btn = ttk.Button(buttons, text="Clear", command=self.on_clear)
        self.clear_btn.pack(side=tk.LEFT, padx=(8, 0))
        self.status_lbl = ttk.Label(buttons, text="Ready", foreground="gray")
        self.status_lbl.pack(side=tk.RIGHT)

        # Output
        ttk.Label(main, text="Result:").pack(anchor=tk.W)
        self.output_text = tk.Text(main, height=14, wrap=tk.WORD, state=tk.DISABLED)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        self.root.after(100, self._poll_queue)

    def _set_output(self, text: str) -> None:
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, text)
        self.output_text.config(state=tk.DISABLED)

    def on_clear(self) -> None:
        self.input_text.delete("1.0", tk.END)
        self._set_output("")
        self.status_lbl.config(text="Ready")

    def on_decrypt(self) -> None:
        ciphertext = self.input_text.get("1.0", tk.END).strip()
        if not ciphertext:
            messagebox.showwarning("No input", "Please enter some ciphertext.")
            return

        self.decode_btn.config(state=tk.DISABLED)
        self.status_lbl.config(text="Decrypting...")

        thread = threading.Thread(
            target=self._run_decrypt,
            args=(ciphertext,),
            daemon=True,
        )
        thread.start()

    def _run_decrypt(self, ciphertext: str) -> None:
        result = ciphey_decrypt(ciphertext)
        self.result_queue.put(result)

    def _poll_queue(self) -> None:
        try:
            result = self.result_queue.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll_queue)
            return

        self.decode_btn.config(state=tk.NORMAL)
        self.status_lbl.config(text="Done")

        if result.success:
            self._set_output(f"Plaintext: {result.plaintext}")
            if result.decoders:
                self._set_output(
                    f"Plaintext: {result.plaintext}\n\n"
                    f"Decoders used: {' -> '.join(result.decoders)}"
                )
            self.status_lbl.config(text="Success", foreground="green")
        else:
            self._set_output(f"Failed to decode:\n{result.error}")
            self.status_lbl.config(text="Failed", foreground="red")

        self.root.after(100, self._poll_queue)


def main() -> None:
    root = tk.Tk()
    CipheyGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
