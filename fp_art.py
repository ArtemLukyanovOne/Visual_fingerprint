from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass
from typing import List, Optional, Tuple

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from PIL import Image, ImageTk


# ----------------------------
# Examples 
# ----------------------------
EXAMPLES = [
    "alpha-key-2026",          # 14
    "ssh-key-demo-01",         # 14
    "lorem-ipsum-1234",        # 15
    "hello-from-msu!",         # 15
    "crypto-lab-sample",       # 17
    "fingerprint-check",       # 17
    "key-material-xyz",        # 16
    "test-vector-A12",         # 14
    "test-vector-B34",         # 14
    "random-seed-7777",        # 16
    "winter-session-26",       # 17
    "matrix-cmc-2026",         # 15
    "network-security!",       # 17
    "hash-me-please",          # 13
    "byte-length-okay",        # 15
    "openbsd-randomart",       # 16
    "private-notes-42",        # 15
    "example-key-string",      # 18
    "another-key-888",         # 15
    "good-luck-have-fun",      # 18
]


# ----------------------------
# Core: text -> SHA256 -> KDF stream -> 64x64 image
# ----------------------------

@dataclass(frozen=True)
class ArtMeta:
    sha256_hex: str
    tag: str
    start: Tuple[int, int]
    end: Tuple[int, int]
    density_name: str


def _make_tag(seed32: bytes) -> str:
    # 3 символа без O/0 и I/1 — хорошо запоминаются
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    b = hashlib.blake2b(seed32, digest_size=3).digest()
    return "".join(alphabet[x % len(alphabet)] for x in b)


def _bytes_len_status(n: int) -> str:
    if n < 12:
        return "слишком коротко"
    if n > 32:
        return "слишком длинно"
    return "OK"


def _wrap(v: int, n: int) -> int:
    return v % n


def _center_of_mass_shift(grid: List[List[int]]) -> Tuple[int, int]:
    """Возвращает circular-shift (dx, dy), чтобы центр массы оказался в центре."""
    size = len(grid)
    total = 0.0
    sx = 0.0
    sy = 0.0
    for y in range(size):
        row = grid[y]
        for x in range(size):
            v = row[x]
            if v > 0:
                total += v
                sx += x * v
                sy += y * v
    if total == 0:
        return 0, 0

    cx = sx / total
    cy = sy / total
    dx = int(round(size / 2 - cx)) % size
    dy = int(round(size / 2 - cy)) % size
    return dx, dy


def _shift_grid(grid: List[List[int]], dx: int, dy: int) -> List[List[int]]:
    size = len(grid)
    out = [[0] * size for _ in range(size)]
    for y in range(size):
        for x in range(size):
            out[(y + dy) % size][(x + dx) % size] = grid[y][x]
    return out


def fingerprint_image_from_text(text: str, density_bytes: int, density_name: str, size: int = 64) -> Tuple[Image.Image, ArtMeta]:
    """
    text -> UTF-8 bytes length check (12..32)
    sha = SHA-256(text)
    stream = SHAKE-256(sha).digest(density_bytes)  # KDF stretch
    Each byte => 4 moves of 2 bits (OpenSSH-style diagonal moves):
        bit0: x sign, bit1: y sign
    Field is torus (wrap-around), then we center by center-of-mass shift.
    """
    raw = text.encode("utf-8")
    n = len(raw)
    if not (12 <= n <= 32):
        raise ValueError(f"Длина ввода должна быть 12–32 байта в UTF-8. Сейчас: {n} байт.")

    sha = hashlib.sha256(raw).digest()  # 32 bytes
    sha_hex = sha.hex()
    tag = _make_tag(sha)

    # Style params from sha (deterministic)
    gamma = 0.65 + (sha[1] / 255) * 0.20  # 0.65..0.85
    stamp_kind = sha[2] & 3               # 0..3
    max_level = 140

    # KDF stretch (your "растяжение" requirement)
    stream = hashlib.shake_256(sha).digest(density_bytes)

    grid: List[List[int]] = [[0] * size for _ in range(size)]

    def inc(x: int, y: int, a: int) -> None:
        v = grid[y][x] + a
        grid[y][x] = max_level if v > max_level else v

    def stamp(x: int, y: int) -> None:
        # thick, readable contour on smooth background
        inc(x, y, 3)

        if stamp_kind == 0:
            # cross
            inc((x + 1) % size, y, 1); inc((x - 1) % size, y, 1)
            inc(x, (y + 1) % size, 1); inc(x, (y - 1) % size, 1)
        elif stamp_kind == 1:
            # diagonals
            inc((x + 1) % size, (y + 1) % size, 1); inc((x - 1) % size, (y - 1) % size, 1)
            inc((x + 1) % size, (y - 1) % size, 1); inc((x - 1) % size, (y + 1) % size, 1)
        elif stamp_kind == 2:
            # 3x3 blob
            for dy in (-1, 0, 1):
                for dx in (-1, 0, 1):
                    inc((x + dx) % size, (y + dy) % size, 1)
        else:
            # slight asymmetry
            inc((x + 1) % size, y, 1); inc(x, (y + 1) % size, 1)

    # Deterministic markers (anchors) — easy to recognize, hard to confuse
    def draw_marker(mx: int, my: int, kind: int) -> None:
        if kind == 0:
            # ring 5x5
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    if abs(dx) == 2 or abs(dy) == 2:
                        inc((mx + dx) % size, (my + dy) % size, 7)
        else:
            # diamond
            for dy in range(-3, 4):
                for dx in range(-3, 4):
                    if abs(dx) + abs(dy) == 3:
                        inc((mx + dx) % size, (my + dy) % size, 7)

    # Place 4 markers using sha + stream to spread them
    markers: List[Tuple[int, int]] = []
    for i in range(4):
        mx = (sha[4 + i] * 17 + stream[10 + i]) % size
        my = (sha[12 + i] * 29 + stream[30 + i]) % size
        for _ in range(12):
            if all((mx - px) ** 2 + (my - py) ** 2 >= 140 for px, py in markers):
                break
            mx = (mx + 13) % size
            my = (my + 31) % size
        markers.append((mx, my))
        draw_marker(mx, my, i & 1)

    # Main walk from center
    x = y = size // 2
    start = (x, y)
    stamp(x, y)

    # Each byte => 4 moves (2 bits per move), like OpenSSH logic
    for byte in stream:
        inp = byte
        for _ in range(4):
            # diagonal move
            x = _wrap(x + (1 if (inp & 0x1) else -1), size)
            y = _wrap(y + (1 if (inp & 0x2) else -1), size)
            stamp(x, y)
            inp >>= 2

    end = (x, y)

    # Center the pattern on the canvas by center-of-mass shift
    dx, dy = _center_of_mass_shift(grid)
    if dx or dy:
        grid = _shift_grid(grid, dx, dy)
        start = (_wrap(start[0] + dx, size), _wrap(start[1] + dy, size))
        end = (_wrap(end[0] + dx, size), _wrap(end[1] + dy, size))

    # Render grayscale with log contrast
    vmax = max(max(row) for row in grid) or 1
    img = Image.new("L", (size, size), 255)
    for yy in range(size):
        for xx in range(size):
            v = grid[yy][xx]
            if v <= 0:
                shade = 255
            else:
                norm = math.log1p(v) / math.log1p(vmax)
                norm = norm ** gamma
                shade = 255 - int(norm * 240)
                shade = 0 if shade < 0 else (255 if shade > 255 else shade)
            img.putpixel((xx, yy), shade)

    # Mark start/end with crosses (after centering)
    def cross(px: int, py: int) -> None:
        for dx2, dy2 in [(0, 0), (1, 0), (-1, 0), (0, 1), (0, -1)]:
            img.putpixel(((px + dx2) % size, (py + dy2) % size), 0)

    cross(start[0], start[1])
    cross(end[0], end[1])

    meta = ArtMeta(
        sha256_hex=sha_hex,
        tag=tag,
        start=start,
        end=end,
        density_name=density_name,
    )
    return img, meta


# ----------------------------
# GUI
# ----------------------------

DENSITY_PRESETS = {
    "Normal (≈2k moves)": 512,   # 512 bytes -> 2048 moves
    "High (≈4k moves)":   1024,  # 1024 bytes -> 4096 moves (your theory target)
    "Ultra (≈8k moves)":  2048,  # 2048 bytes -> 8192 moves
}


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Graphical Fingerprint 64×64")
        self.minsize(980, 700)

        # Theme + spacing
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Sub.TLabel", font=("Segoe UI", 10))
        style.configure("Mono.TLabel", font=("Consolas", 10))
        style.configure("TButton", padding=8)
        style.configure("TEntry", padding=6)

        self.base_img: Optional[Image.Image] = None
        self.tk_img: Optional[ImageTk.PhotoImage] = None
        self.meta: Optional[ArtMeta] = None

        self.zoom_var = tk.IntVar(value=14)
        self.density_var = tk.StringVar(value="High (≈4k moves)")

        self._build_ui()
        self._update_len_label()

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=16)
        root.pack(fill=tk.BOTH, expand=True)

        # Header
        ttk.Label(root, text="Graphical Fingerprint", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            root,
            text="Ввод: любой текст (12–32 байта UTF-8). Вывод: fingerprint (SHA-256) → 64×64 картинка. "
                 "Плотность регулируется KDF-растяжением (SHAKE-256).",
            style="Sub.TLabel"
        ).pack(anchor="w", pady=(6, 14))

        # Input row
        row = ttk.Frame(root)
        row.pack(fill=tk.X)

        ttk.Label(row, text="Input text:").pack(side=tk.LEFT)
        self.entry = ttk.Entry(row)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 10))
        self.entry.bind("<KeyRelease>", lambda _e: self._update_len_label())

        ttk.Button(row, text="🎲 Example", command=self.on_example).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(row, text="Generate", command=self.on_generate).pack(side=tk.LEFT)

        # Info row (bytes + status + density)
        info = ttk.Frame(root)
        info.pack(fill=tk.X, pady=(10, 10))

        self.len_label = ttk.Label(info, text="Bytes: 0 (…)", style="Sub.TLabel")
        self.len_label.pack(side=tk.LEFT)

        ttk.Label(info, text="   Density:", style="Sub.TLabel").pack(side=tk.LEFT, padx=(18, 6))
        self.density_box = ttk.Combobox(
            info,
            textvariable=self.density_var,
            values=list(DENSITY_PRESETS.keys()),
            state="readonly",
            width=18
        )
        self.density_box.pack(side=tk.LEFT)
        self.density_box.bind("<<ComboboxSelected>>", lambda _e: self._maybe_rerender_hint())

        # Meta row
        meta_row = ttk.Frame(root)
        meta_row.pack(fill=tk.X, pady=(0, 12))
        self.tag_label = ttk.Label(meta_row, text="TAG: —", style="Mono.TLabel")
        self.tag_label.pack(side=tk.LEFT)
        self.pos_label = ttk.Label(meta_row, text="   S: —   E: —", style="Mono.TLabel")
        self.pos_label.pack(side=tk.LEFT, padx=(12, 0))
        self.sha_label = ttk.Label(meta_row, text="   SHA256: —", style="Mono.TLabel")
        self.sha_label.pack(side=tk.LEFT, padx=(12, 0))

        # Controls row (zoom + save)
        ctrl = ttk.Frame(root)
        ctrl.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(ctrl, text="Zoom:", style="Sub.TLabel").pack(side=tk.LEFT)
        zoom = ttk.Scale(ctrl, from_=4, to=40, orient=tk.HORIZONTAL, command=self._on_zoom)
        zoom.set(self.zoom_var.get())
        zoom.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 10))

        self.zoom_label = ttk.Label(ctrl, text=f"{self.zoom_var.get()}×", style="Sub.TLabel")
        self.zoom_label.pack(side=tk.LEFT, padx=(0, 12))

        ttk.Button(ctrl, text="Save PNG (64×64)", command=self.on_save).pack(side=tk.LEFT)

        # Canvas (scrollable, centered drawing)
        area = ttk.Frame(root)
        area.pack(fill=tk.BOTH, expand=True)

        self.canvas = tk.Canvas(area, bg="#f5f6f8", highlightthickness=1, highlightbackground="#d8dbe0")
        self.hbar = ttk.Scrollbar(area, orient=tk.HORIZONTAL, command=self.canvas.xview)
        self.vbar = ttk.Scrollbar(area, orient=tk.VERTICAL, command=self.canvas.yview)
        self.canvas.configure(xscrollcommand=self.hbar.set, yscrollcommand=self.vbar.set)

        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.vbar.grid(row=0, column=1, sticky="ns")
        self.hbar.grid(row=1, column=0, sticky="ew")

        area.rowconfigure(0, weight=1)
        area.columnconfigure(0, weight=1)

        # Zoom by Ctrl + Wheel
        self.canvas.bind("<Control-MouseWheel>", self._ctrl_wheel_zoom)  # Win/mac
        self.canvas.bind("<Control-Button-4>", lambda _e: self._zoom_step(+1))  # Linux
        self.canvas.bind("<Control-Button-5>", lambda _e: self._zoom_step(-1))  # Linux

        # Recenter on resize
        self.canvas.bind("<Configure>", lambda _e: self._render())

        self._placeholder()

    def _placeholder(self) -> None:
        self.canvas.delete("all")
        self.canvas.create_text(
            24, 24, anchor="nw",
            text="Тут появится изображение 64×64.\n\n"
                 "• Длина ввода: 12–32 байта (UTF-8)\n"
                 "• Плотность: Normal / High / Ultra\n"
                 "• Zoom: слайдер или Ctrl + колёсико\n"
                 "• Save PNG сохраняет оригинальные 64×64",
            fill="#48505a", font=("Segoe UI", 11)
        )

    def _update_len_label(self) -> None:
        n = len(self.entry.get().encode("utf-8"))
        status = _bytes_len_status(n)
        self.len_label.config(text=f"Bytes: {n} ({status})")

    def _maybe_rerender_hint(self) -> None:
        # не автогенерируем, просто мягко намекаем
        if self.base_img is not None:
            # если уже есть картинка — можно перегенерить вручную (это детерминированно)
            pass

    def on_example(self) -> None:
        s = random.choice(EXAMPLES)  # равный шанс получить любой из ~20
        self.entry.delete(0, tk.END)
        self.entry.insert(0, s)
        self._update_len_label()

    def on_generate(self) -> None:
        text = self.entry.get()
        self._update_len_label()

        preset_name = self.density_var.get()
        density_bytes = DENSITY_PRESETS.get(preset_name, 1024)

        try:
            img, meta = fingerprint_image_from_text(text, density_bytes=density_bytes, density_name=preset_name, size=64)
        except Exception as e:
            messagebox.showerror("Неверный ввод", str(e))
            return

        self.base_img = img
        self.meta = meta

        self.tag_label.config(text=f"TAG: {meta.tag}   ({meta.density_name})")
        self.pos_label.config(text=f"   S: {meta.start}   E: {meta.end}")
        self.sha_label.config(text=f"   SHA256: {meta.sha256_hex[:24]}…")

        self._render()

    def _on_zoom(self, val: str) -> None:
        self.zoom_var.set(int(float(val)))
        self.zoom_label.config(text=f"{self.zoom_var.get()}×")
        self._render()

    def _zoom_step(self, delta: int) -> None:
        z = self.zoom_var.get() + delta
        z = 4 if z < 4 else (40 if z > 40 else z)
        self.zoom_var.set(z)
        self.zoom_label.config(text=f"{z}×")
        self._render()

    def _ctrl_wheel_zoom(self, event: tk.Event) -> None:
        self._zoom_step(+1 if event.delta > 0 else -1)

    def _render(self) -> None:
        if self.base_img is None:
            return

        z = max(1, int(self.zoom_var.get()))
        scaled = self.base_img.resize((64 * z, 64 * z), resample=Image.NEAREST)
        self.tk_img = ImageTk.PhotoImage(scaled)

        self.canvas.delete("all")

        # Center the image in the visible canvas if it's smaller; otherwise anchor at (0,0) with scroll
        cw = max(1, self.canvas.winfo_width())
        ch = max(1, self.canvas.winfo_height())
        iw, ih = scaled.size

        x0 = (cw - iw) // 2 if iw < cw else 0
        y0 = (ch - ih) // 2 if ih < ch else 0

        self.canvas.create_image(x0, y0, anchor="nw", image=self.tk_img)

        # scrollregion must include both canvas and image bounds
        sr_w = max(iw + x0, cw)
        sr_h = max(ih + y0, ch)
        self.canvas.config(scrollregion=(0, 0, sr_w, sr_h))

    def on_save(self) -> None:
        if self.base_img is None or self.meta is None:
            messagebox.showinfo("Нет изображения", "Сначала нажмите Generate.")
            return

        default_name = f"fp_{self.meta.tag}.png"
        path = filedialog.asksaveasfilename(
            title="Сохранить PNG (64×64)",
            initialfile=default_name,
            defaultextension=".png",
            filetypes=[("PNG image", "*.png")]
        )
        if not path:
            return

        try:
            self.base_img.save(path)
        except Exception as e:
            messagebox.showerror("Ошибка сохранения", str(e))
            return

        messagebox.showinfo("Готово", f"Сохранено:\n{path}")


def main() -> None:
    App().mainloop()


if __name__ == "__main__":
    main()
