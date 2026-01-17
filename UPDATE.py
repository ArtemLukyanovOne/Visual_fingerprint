import argparse
import base64
import binascii
import colorsys
import hashlib
import math
import random
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from PIL import Image, ImageTk

# ----------------------------
# Examples
# ----------------------------
EXAMPLES = [
    "alpha-key-2026",
    "ssh-key-demo-01",
    "lorem-ipsum-1234",
    "hello-from-msu!",
    "crypto-lab-sample",
    "fingerprint-check",
    "key-material-xyz",
    "test-vector-A12",
    "test-vector-B34",
    "random-seed-7777",
    "winter-session-26",
    "matrix-cmc-2026",
    "network-security!",
    "hash-me-please",
    "byte-length-okay",
    "openbsd-randomart",
    "private-notes-42",
    "example-key-string",
    "another-key-888",
    "good-luck-have-fun",
]

# HEX fingerprints like: 00:11:22:... or with spaces
HEX_RE = re.compile(r"^[0-9a-fA-F:\s]+$")

# SSH public key: "ssh-ed25519 <base64> [comment]" or "ssh-rsa ..." or "ecdsa-..."
SSH_PUBKEY_RE = re.compile(r"^(ssh-[a-z0-9-]+|ecdsa-[a-z0-9-]+)\s+([A-Za-z0-9+/=]+)(?:\s+.*)?$")


# ----------------------------
# Data classes
# ----------------------------

@dataclass(frozen=True)
class ArtMeta:
    sha256_hex: str
    tag: str
    start: Tuple[int, int]
    end: Tuple[int, int]
    density_name: str
    mode_name: str


@dataclass(frozen=True)
class ParsedInput:
    fingerprint: bytes  # numeric fingerprint (12..32 bytes) used as input to visual algorithm
    kind: str  # "hex-fingerprint" | "ssh-public-key" | "text" | "file-bytes"
    details: str  # for UI/CLI


# ----------------------------
# Helpers
# ----------------------------

def _make_tag(seed32: bytes) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no O/0 and I/1
    b = hashlib.blake2b(seed32, digest_size=3).digest()
    return "".join(alphabet[x % len(alphabet)] for x in b)


def _wrap(v: int, n: int) -> int:
    return v % n


def _center_of_mass_shift(grid: List[List[int]]) -> Tuple[int, int]:
    """Circular shift (dx,dy) to move center of mass to center."""
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


def _shift_grid_int(grid: List[List[int]], dx: int, dy: int) -> List[List[int]]:
    size = len(grid)
    out = [[0] * size for _ in range(size)]
    for y in range(size):
        for x in range(size):
            out[(y + dy) % size][(x + dx) % size] = grid[y][x]
    return out


def _shift_grid_float(grid: List[List[float]], dx: int, dy: int) -> List[List[float]]:
    size = len(grid)
    out = [[0.0] * size for _ in range(size)]
    for y in range(size):
        for x in range(size):
            out[(y + dy) % size][(x + dx) % size] = grid[y][x]
    return out


# ----------------------------
# Input parsing
# ----------------------------

def parse_user_input(s: str) -> ParsedInput:
    """
    Accepts:
      1) HEX fingerprint: "00:11:..." (12..32 bytes after decode)
      2) SSH public key: "ssh-ed25519 AAAA... comment" -> SHA-256(blob) (32 bytes)
      3) Any text -> SHA-256(utf8) (32 bytes)

    Returns fingerprint bytes in range 12..32 to feed the visual algorithm.
    """
    s = s.strip()
    if not s:
        raise ValueError("Пустой ввод.")

    # 1) HEX fingerprint
    if HEX_RE.fullmatch(s) is not None:
        hex_only = re.sub(r"[^0-9a-fA-F]", "", s)
        if len(hex_only) % 2 != 0:
            raise ValueError("HEX fingerprint должен иметь чётное число hex-символов (байты по 2 символа).")
        try:
            fp = bytes.fromhex(hex_only)
        except ValueError as e:
            raise ValueError("Не удалось распознать HEX fingerprint.") from e

        if not (12 <= len(fp) <= 32):
            raise ValueError(f"HEX fingerprint должен быть 12–32 байта. Сейчас: {len(fp)} байт.")
        return ParsedInput(fp, "hex-fingerprint", f"HEX fingerprint: {len(fp)} bytes")

    # 2) SSH public key
    m = SSH_PUBKEY_RE.match(s)
    if m:
        key_type = m.group(1)
        b64 = m.group(2)
        try:
            blob = base64.b64decode(b64, validate=True)
        except binascii.Error as e:
            raise ValueError("Похоже на SSH public key, но base64 часть невалидна.") from e
        fp = hashlib.sha256(blob).digest()
        return ParsedInput(fp, "ssh-public-key",
                           f"SSH public key ({key_type}): blob={len(blob)} bytes → SHA-256 (32 bytes)")

    # 3) Text fallback
    raw = s.encode("utf-8")
    fp = hashlib.sha256(raw).digest()
    return ParsedInput(fp, "text", f"Text: utf8={len(raw)} bytes → SHA-256 (32 bytes)")


def parse_file_input(path: str) -> ParsedInput:
    """
    Reads bytes from file. If it looks like SSH public key line, parse as SSH public key.
    Otherwise hashes raw bytes as fingerprint input (deterministic).
    """
    with open(path, "rb") as f:
        data = f.read()

    # Try decode as text and parse SSH public key
    try:
        text = data.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        text = ""

    if text:
        # If file is a public key line -> parse it
        m = SSH_PUBKEY_RE.match(text)
        if m:
            key_type = m.group(1)
            b64 = m.group(2)
            blob = base64.b64decode(b64, validate=True)
            fp = hashlib.sha256(blob).digest()
            return ParsedInput(fp, "ssh-public-key",
                               f"File SSH public key ({key_type}): blob={len(blob)} bytes → SHA-256 (32 bytes)")
        # If file contains hex-ish fingerprint line
        if HEX_RE.fullmatch(text) is not None:
            return parse_user_input(text)

    # Otherwise treat file bytes as input material:
    # produce 32-byte fingerprint, then the visual algorithm will normalize again.
    fp = hashlib.sha256(data).digest()
    return ParsedInput(fp, "file-bytes", f"File bytes: {len(data)} bytes → SHA-256 (32 bytes)")


# ----------------------------
# Visual algorithm (Drunken Bishop adapted to 64x64) with HSV default
# ----------------------------
def fingerprint_image_from_fingerprint(
        fp: bytes,
        density_bytes: int,
        density_name: str,
        *,
        size: int = 64,
        mode: str = "hsv",
) -> Tuple[Image.Image, ArtMeta]:
    """
    Создает тепловую карту (heatmap) с плавными градиентами.
    Основные принципы:
    1. Яркость (Value) соответствует логарифмической интенсивности
    2. Оттенок (Hue) плавно меняется от холодного к теплому вместе с яркостью
    3. Насыщенность (Saturation) высокая, но контролируемая для естественных цветов
    4. Гауссово размытие для плавных переходов
    5. Фоновый градиент для заполнения пустых областей
    """
    if not (12 <= len(fp) <= 32):
        raise ValueError(f"fingerprint must be 12..32 bytes, got {len(fp)}")

    seed = hashlib.sha256(fp).digest()
    sha_hex = seed.hex()
    tag = _make_tag(seed)

    # Стилевые параметры из seed
    gamma = 0.7 + (seed[1] / 255) * 0.25  # Более мягкая гамма
    stamp_kind = seed[2] & 3
    max_level = 120  # Уменьшаем максимальный уровень для более плавных переходов

    # KDF для расширения потока
    stream = hashlib.shake_256(seed).digest(density_bytes)

    # Инициализация сеток
    intensity: List[List[int]] = [[0] * size for _ in range(size)]
    visits: List[List[int]] = [[0] * size for _ in range(size)]
    vx: List[List[float]] = [[0.0] * size for _ in range(size)]
    vy: List[List[float]] = [[0.0] * size for _ in range(size)]

    def inc_int(x: int, y: int, a: int) -> None:
        v = intensity[y][x] + a
        intensity[y][x] = max_level if v > max_level else v

    def stamp(x: int, y: int) -> None:
        inc_int(x, y, 2)  # Уменьшаем основной вклад для более тонких линий

        # Более мягкие штампы для плавности
        if stamp_kind == 0:
            inc_int((x + 1) % size, y, 1)
            inc_int((x - 1) % size, y, 1)
        elif stamp_kind == 1:
            inc_int((x + 1) % size, (y + 1) % size, 1)
            inc_int((x - 1) % size, (y - 1) % size, 1)
        elif stamp_kind == 2:
            inc_int((x + 1) % size, y, 1)
            inc_int(x, (y + 1) % size, 1)
        else:
            pass  # Минимальный штамп

    def draw_marker(mx0: int, my0: int, kind: int) -> None:
        # Мягкие метки для структурных элементов
        for dy0 in range(-2, 3):
            for dx0 in range(-2, 3):
                distance = abs(dx0) + abs(dy0)
                if distance <= 2:
                    inc_int((mx0 + dx0) % size, (my0 + dy0) % size, 5 - distance)

    # Размещаем структурные элементы
    markers: List[Tuple[int, int]] = []
    for i in range(4):
        mx0 = (seed[4 + i] * 17 + stream[10 + i]) % size
        my0 = (seed[12 + i] * 29 + stream[30 + i]) % size
        for _ in range(8):
            if all((mx0 - px) ** 2 + (my0 - py) ** 2 >= 100 for px, py in markers):
                break
            mx0 = (mx0 + 17) % size
            my0 = (my0 + 23) % size
        markers.append((mx0, my0))
        draw_marker(mx0, my0, i & 1)

    # Начинаем обход из центра
    x = y = size // 2
    start = (x, y)

    visits[y][x] += 1
    stamp(x, y)

    # Случайное блуждание
    for byte in stream:
        inp = byte
        for _ in range(4):
            dx = 1 if (inp & 0x1) else -1
            dy = 1 if (inp & 0x2) else -1

            x = _wrap(x + dx, size)
            y = _wrap(y + dy, size)

            visits[y][x] += 1
            vx[y][x] += float(dx)
            vy[y][x] += float(dy)

            stamp(x, y)
            inp >>= 2

    end = (x, y)

    # Центрирование
    dxs, dys = _center_of_mass_shift(intensity)
    if dxs or dys:
        intensity = _shift_grid_int(intensity, dxs, dys)
        visits = _shift_grid_int(visits, dxs, dys)
        vx = _shift_grid_float(vx, dxs, dys)
        vy = _shift_grid_float(vy, dxs, dys)
        start = (_wrap(start[0] + dxs, size), _wrap(start[1] + dys, size))
        end = (_wrap(end[0] + dxs, size), _wrap(end[1] + dys, size))

    # Нормализация интенсивности
    vmax = max(max(row) for row in intensity) or 1

    if mode.lower() == "gray":
        # Градации серого (оставляем как было)
        img = Image.new("L", (size, size), 255)
        for yy in range(size):
            for xx in range(size):
                v = intensity[yy][xx]
                if v <= 0:
                    shade = 255
                else:
                    norm = math.log1p(v) / math.log1p(vmax)
                    norm = norm ** gamma
                    shade = 255 - int(norm * 240)
                    shade = 0 if shade < 0 else (255 if shade > 255 else shade)
                img.putpixel((xx, yy), shade)
        img = img.convert("RGB")
        mode_name = "Grayscale"
    else:
        # СОЗДАЕМ НАСТОЯЩУЮ ТЕПЛОВУЮ КАРТУ
        img = Image.new("RGB", (size, size))

        # 1. Параметры тепловой карты (настраиваемые)
        H_COLD = 0.7  # Фиолетовый
        H_WARM = 0.0  # Красно-оранжевый
        SATURATION = 0.85
        V_MIN = 0.12
        V_MAX = 0.95

        # 2. Создаем плавное поле интенсивности с гауссовым размытием
        # Сначала нормализуем интенсивность
        normalized = [[0.0] * size for _ in range(size)]
        for yy in range(size):
            for xx in range(size):
                v = intensity[yy][xx]
                if v <= 0:
                    normalized[yy][xx] = 0.0
                else:
                    # Логарифмическая нормализация + гамма-коррекция
                    norm = math.log1p(v) / math.log1p(vmax)
                    normalized[yy][xx] = norm ** gamma

        # 3. Применяем простое размытие для плавности
        smoothed = [[0.0] * size for _ in range(size)]
        kernel = [(0, 0, 0.4), (-1, 0, 0.15), (1, 0, 0.15), (0, -1, 0.15), (0, 1, 0.15)]

        for yy in range(size):
            for xx in range(size):
                total = 0.0
                weight_sum = 0.0
                for dy, dx, weight in kernel:
                    ny = (yy + dy) % size
                    nx = (xx + dx) % size
                    total += normalized[ny][nx] * weight
                    weight_sum += weight
                smoothed[yy][xx] = total / weight_sum

        # 4. Добавляем фоновый радиальный градиент
        center_x, center_y = size // 2, size // 2
        max_dist = math.sqrt(center_x ** 2 + center_y ** 2)

        for yy in range(size):
            for xx in range(size):
                # Текущее значение интенсивности
                intensity_val = smoothed[yy][xx]

                # Радиальный градиент от центра
                dx = xx - center_x
                dy = yy - center_y
                distance = math.sqrt(dx * dx + dy * dy)
                radial = 1.0 - (distance / max_dist) * 0.3  # Слабый градиент

                # Комбинируем интенсивность с радиальным градиентом
                combined = intensity_val * 0.7 + radial * 0.3

                # Яркость: от V_MIN до V_MAX
                V = V_MIN + combined * (V_MAX - V_MIN)

                # Оттенок: плавно меняется от холодного к теплому
                # Используем комбинацию интенсивности и положения
                intensity_factor = intensity_val
                radial_factor = 1.0 - radial

                # Вес интенсивности выше для горячих зон
                if intensity_val > 0.5:
                    blend = intensity_factor * 0.8 + radial_factor * 0.2
                else:
                    blend = intensity_factor * 0.4 + radial_factor * 0.6

                H = H_COLD + blend * (H_WARM - H_COLD)
                if H < 0:
                    H += 1.0

                # Насыщенность: постоянная высокая, но контролируемая
                S = SATURATION

                # Корректируем насыщенность для экстремальных значений
                if V > 0.9:
                    S = SATURATION * 0.8  # Слегка приглушаем очень светлые области
                elif V < 0.3:
                    S = SATURATION * 0.9  # Темные области чуть менее насыщенные

                # Преобразуем HSV в RGB
                r, g, b = colorsys.hsv_to_rgb(H, S, V)

                # Легкая коррекция для более естественных цветов
                # Уменьшаем кислотность зеленых тонов
                if 0.25 < H < 0.45:  # Зеленая область
                    g = g * 0.95
                    r = r * 1.05

                # Ограничиваем значения
                r = min(max(r, 0.0), 1.0)
                g = min(max(g, 0.0), 1.0)
                b = min(max(b, 0.0), 1.0)

                img.putpixel((xx, yy), (int(r * 255), int(g * 255), int(b * 255)))

        mode_name = "Heatmap (smooth gradient)"

    # Отмечаем начало и конец (тонко, чтобы не нарушать градиент)
    def subtle_cross(px: int, py: int, color_idx: int) -> None:
        # Тонкие метки в стиле тепловой карты
        colors = [(30, 30, 30), (60, 60, 60)]  # Темно-серые, а не черные
        color = colors[color_idx]
        for dx0, dy0 in [(0, 0), (1, 0), (-1, 0), (0, 1), (0, -1)]:
            current = img.getpixel(((px + dx0) % size, (py + dy0) % size))
            # Смешиваем с текущим цветом для тонкости
            mixed = (
                int(current[0] * 0.7 + color[0] * 0.3),
                int(current[1] * 0.7 + color[1] * 0.3),
                int(current[2] * 0.7 + color[2] * 0.3)
            )
            img.putpixel(((px + dx0) % size, (py + dy0) % size), mixed)

    subtle_cross(start[0], start[1], 0)
    subtle_cross(end[0], end[1], 1)

    meta = ArtMeta(
        sha256_hex=sha_hex,
        tag=tag,
        start=start,
        end=end,
        density_name=density_name,
        mode_name=mode_name,
    )
    return img, meta


# ----------------------------
# GUI
# ----------------------------

DENSITY_PRESETS = {
    "Normal (≈2k moves)": 512,
    "High (≈4k moves)": 1024,
    "Ultra (≈8k moves)": 2048,
}

MODE_PRESETS = {
    "HSV (color)": "hsv",
    "Grayscale": "gray",
}


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Visual Fingerprint 64×64")
        self.minsize(980, 720)

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
        self.parsed: Optional[ParsedInput] = None

        self.zoom_var = tk.IntVar(value=14)
        self.density_var = tk.StringVar(value="High (≈4k moves)")
        self.mode_var = tk.StringVar(value="HSV (color)")  # default HSV

        self.zoom_scale: Optional[ttk.Scale] = None

        self._build_ui()
        self._update_input_info()

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=16)
        root.pack(fill=tk.BOTH, expand=True)

        ttk.Label(root, text="Visual Fingerprint", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            root,
            text="Ввод: HEX fingerprint (12–32 байта) / SSH public key / текст / файл. "
                 "Вывод: 64×64 randomart (default: HSV).",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(6, 14))

        # Input row
        row = ttk.Frame(root)
        row.pack(fill=tk.X)

        ttk.Label(row, text="Input:").pack(side=tk.LEFT)
        self.entry = ttk.Entry(row)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 10))
        self.entry.bind("<KeyRelease>", lambda _e: self._update_input_info())

        ttk.Button(row, text="📄 Load file", command=self.on_load_file).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(row, text="🎲 Example", command=self.on_example).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(row, text="Generate", command=self.on_generate).pack(side=tk.LEFT)

        # Info row
        info = ttk.Frame(root)
        info.pack(fill=tk.X, pady=(10, 10))
        self.info_label = ttk.Label(info, text="—", style="Sub.TLabel")
        self.info_label.pack(side=tk.LEFT)

        # Controls (density + mode)
        opts = ttk.Frame(root)
        opts.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(opts, text="Density:", style="Sub.TLabel").pack(side=tk.LEFT)
        self.density_box = ttk.Combobox(
            opts,
            textvariable=self.density_var,
            values=list(DENSITY_PRESETS.keys()),
            state="readonly",
            width=18,
        )
        self.density_box.pack(side=tk.LEFT, padx=(8, 16))

        ttk.Label(opts, text="Mode:", style="Sub.TLabel").pack(side=tk.LEFT)
        self.mode_box = ttk.Combobox(
            opts,
            textvariable=self.mode_var,
            values=list(MODE_PRESETS.keys()),
            state="readonly",
            width=14,
        )
        self.mode_box.pack(side=tk.LEFT, padx=(8, 0))

        # Meta row
        meta_row = ttk.Frame(root)
        meta_row.pack(fill=tk.X, pady=(0, 12))
        self.tag_label = ttk.Label(meta_row, text="TAG: —", style="Mono.TLabel")
        self.tag_label.pack(side=tk.LEFT)
        self.pos_label = ttk.Label(meta_row, text="   S: —   E: —", style="Mono.TLabel")
        self.pos_label.pack(side=tk.LEFT, padx=(12, 0))
        self.sha_label = ttk.Label(meta_row, text="   SHA256: —", style="Mono.TLabel")
        self.sha_label.pack(side=tk.LEFT, padx=(12, 0))

        # Controls row (zoom + save)  --- FIX: zoom_label exists BEFORE Scale callback may fire
        ctrl = ttk.Frame(root)
        ctrl.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(ctrl, text="Zoom:", style="Sub.TLabel").pack(side=tk.LEFT)

        self.zoom_label = ttk.Label(ctrl, text=f"{self.zoom_var.get()}×", style="Sub.TLabel")
        self.zoom_label.pack(side=tk.RIGHT, padx=(0, 12))

        ttk.Button(ctrl, text="Save PNG (64×64)", command=self.on_save).pack(side=tk.RIGHT)

        self.zoom_scale = ttk.Scale(ctrl, from_=4, to=40, orient=tk.HORIZONTAL, command=self._on_zoom)
        self.zoom_scale.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 10))
        self.zoom_scale.set(self.zoom_var.get())

        # Canvas
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
        self.canvas.bind("<Configure>", lambda _e: self._render())

        self._placeholder()

    def _placeholder(self) -> None:
        self.canvas.delete("all")
        self.canvas.create_text(
            24, 24, anchor="nw",
            text=(
                "Тут появится изображение 64×64.\n\n"
                "Поддерживаемый ввод:\n"
                "• HEX fingerprint: 00:11:...:ff (12–32 байта)\n"
                "• SSH public key: ssh-ed25519 AAAA... (fingerprint=SHA-256(blob))\n"
                "• Любой текст: fingerprint=SHA-256(UTF-8)\n"
                "• Файл: Load file (public key / fingerprint / или просто байты)\n\n"
                "Default режим: HSV (цвет). Zoom: слайдер или Ctrl+колёсико.\n"
                "Save PNG сохраняет оригинальные 64×64."
            ),
            fill="#48505a",
            font=("Segoe UI", 11),
        )

    def _update_input_info(self) -> None:
        s = self.entry.get().strip()
        if not s:
            self.info_label.config(text="Введите HEX fingerprint / SSH public key / текст (или загрузите файл).")
            self.parsed = None
            return
        try:
            parsed = parse_user_input(s)
        except Exception as e:
            self.parsed = None
            self.info_label.config(text=f"Ошибка ввода: {e}")
            return
        self.parsed = parsed
        self.info_label.config(text=parsed.details)

    def on_load_file(self) -> None:
        path = filedialog.askopenfilename(title="Выберите файл ключа/отпечатка")
        if not path:
            return
        try:
            parsed = parse_file_input(path)
        except Exception as e:
            messagebox.showerror("Ошибка чтения файла", str(e))
            return
        self.parsed = parsed
        self.entry.delete(0, tk.END)
        self.entry.insert(0, path)
        self.info_label.config(text=parsed.details + " (loaded)")

    def on_example(self) -> None:
        s = random.choice(EXAMPLES)
        self.entry.delete(0, tk.END)
        self.entry.insert(0, s)
        self._update_input_info()

    def on_generate(self) -> None:
        # If entry is a path and last action was Load file, parsed already stored.
        # Otherwise parse from entry text.
        s = self.entry.get().strip()
        if not self.parsed or (self.parsed.kind != "file-bytes" and self.parsed.kind != "ssh-public-key"):
            # Try parse text input
            try:
                self.parsed = parse_user_input(s)
            except Exception as e:
                messagebox.showerror("Неверный ввод", str(e))
                return

        preset_name = self.density_var.get()
        density_bytes = DENSITY_PRESETS.get(preset_name, 1024)

        mode_key = MODE_PRESETS.get(self.mode_var.get(), "hsv")

        try:
            img, meta = fingerprint_image_from_fingerprint(
                self.parsed.fingerprint,
                density_bytes=density_bytes,
                density_name=preset_name,
                size=64,
                mode=mode_key,
            )
        except Exception as e:
            messagebox.showerror("Ошибка генерации", str(e))
            return

        self.base_img = img
        self.meta = meta

        self.tag_label.config(text=f"TAG: {meta.tag}   ({meta.density_name}, {meta.mode_name})")
        self.pos_label.config(text=f"   S: {meta.start}   E: {meta.end}")
        self.sha_label.config(text=f"   Seed SHA256: {meta.sha256_hex[:24]}…")

        self._render()

    def _on_zoom(self, val: str) -> None:
        # hard guard for early callback on some Tk versions
        if not hasattr(self, "zoom_label"):
            return
        self.zoom_var.set(int(float(val)))
        self.zoom_label.config(text=f"{self.zoom_var.get()}×")
        self._render()

    def _zoom_step(self, delta: int) -> None:
        z = self.zoom_var.get() + delta
        z = 4 if z < 4 else (40 if z > 40 else z)
        self.zoom_var.set(z)
        if hasattr(self, "zoom_label"):
            self.zoom_label.config(text=f"{z}×")
        if self.zoom_scale is not None:
            self.zoom_scale.set(z)
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

        cw = max(1, self.canvas.winfo_width())
        ch = max(1, self.canvas.winfo_height())
        iw, ih = scaled.size

        x0 = (cw - iw) // 2 if iw < cw else 0
        y0 = (ch - ih) // 2 if ih < ch else 0

        self.canvas.create_image(x0, y0, anchor="nw", image=self.tk_img)

        sr_w = max(iw + x0, cw)
        sr_h = max(ih + y0, ch)
        self.canvas.config(scrollregion=(0, 0, sr_w, sr_h))

    def on_save(self) -> None:
        if self.base_img is None or self.meta is None:
            messagebox.showinfo("Нет изображения", "Сначала нажмите Generate.")
            return

        default_name = f"fp_{self.meta.tag}_{self.meta.mode_name.lower()}.png"
        path = filedialog.asksaveasfilename(
            title="Сохранить PNG (64×64)",
            initialfile=default_name,
            defaultextension=".png",
            filetypes=[("PNG image", "*.png")],
        )
        if not path:
            return

        try:
            self.base_img.save(path)
        except Exception as e:
            messagebox.showerror("Ошибка сохранения", str(e))
            return

        messagebox.showinfo("Готово", f"Сохранено:\n{path}")


# ----------------------------
# CLI
# ----------------------------

def run_cli(args: argparse.Namespace) -> int:
    if args.file:
        parsed = parse_file_input(args.file)
    else:
        if not args.input:
            raise ValueError("Для CLI нужен --input или --file.")
        parsed = parse_user_input(args.input)

    density_name = args.density
    density_bytes = DENSITY_PRESETS.get(density_name, 1024)

    mode = args.mode.lower()
    if mode not in ("hsv", "gray"):
        raise ValueError("mode должен быть hsv или gray")

    img, meta = fingerprint_image_from_fingerprint(
        parsed.fingerprint,
        density_bytes=density_bytes,
        density_name=density_name,
        size=64,
        mode=mode,
    )

    out = args.out
    img.save(out)

    if not args.quiet:
        print(f"Input: {parsed.kind} | {parsed.details}")
        print(f"Mode: {meta.mode_name}, Density: {meta.density_name}")
        print(f"TAG: {meta.tag}")
        print(f"Seed SHA256: {meta.sha256_hex}")
        print(f"Start: {meta.start}  End: {meta.end}")
        print(f"Saved: {out}")

    return 0


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Visual Fingerprint 64x64 (Drunken Bishop adapted). Default GUI, optional CLI.",
    )
    p.add_argument("--input", "-i", help="Input string: HEX fingerprint / SSH public key / arbitrary text")
    p.add_argument("--file", "-f", help="Read input from file (public key / fingerprint / raw bytes)")
    p.add_argument("--out", "-o", default="fingerprint.png", help="Output PNG path (CLI). Default: fingerprint.png")
    p.add_argument(
        "--density",
        default="High (≈4k moves)",
        choices=list(DENSITY_PRESETS.keys()),
        help="Density preset (controls SHAKE-256 output bytes)",
    )
    p.add_argument("--mode", default="hsv", choices=["hsv", "gray"], help="Render mode for CLI (default: hsv)")
    p.add_argument("--quiet", action="store_true", help="Less console output (CLI)")
    p.add_argument("--gui", action="store_true", help="Force GUI even if CLI args present")
    return p


def main() -> None:
    parser = build_argparser()
    args = parser.parse_args()

    # If user forces GUI or no CLI-relevant args -> GUI
    if args.gui or (not args.input and not args.file):
        App().mainloop()
        return

    # CLI mode
    try:
        run_cli(args)
    except Exception as e:
        print(f"Error: {e}")
        raise


if __name__ == "__main__":
    main()
