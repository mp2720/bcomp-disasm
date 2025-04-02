#!/usr/bin/env python3

import sys

from PIL import Image
from typing import cast

MARGIN_LEFT = 4
MARGIN_TOP = 6
GLYPH_WIDTH = 7
GLYPH_HEIGHT = 10
LEADING = 7
ROWS = 14


def read_glyph(img: Image.Image, lt_x: int, lt_y: int) -> str:
    s = ''
    for y in range(GLYPH_HEIGHT):
        for x in range(GLYPH_WIDTH):
            # pyright ...
            r, g, b, a = cast(tuple, img.getpixel((lt_x + x, lt_y + y)))
            s += '#' if a > 128 else ' '
        s += '\n'
    return s


def scan(img: Image.Image, out_file):
    interpr: dict[str, str] = {}

    def get_glyph_char(glyph: str) -> str:
        if glyph not in interpr:
            print(glyph)
            char = input(
                'Что это за символ? '
            ).strip()
            assert char, 'введена пустая строка'
            interpr[glyph] = char

        return interpr[glyph]

    def process_word(x: int, y: int, glyphs_cnt: int) -> str | None:
        ret = ''
        for j in range(glyphs_cnt):
            sx = j * (GLYPH_WIDTH + 1)
            glyph = read_glyph(img, x + sx, y)
            if glyph.isspace():
                return None
            ret += get_glyph_char(glyph)
        return ret

    def process_row(x: int, y: int):
        addr = process_word(x, y, 3)
        data = process_word(x + 56, y, 4)

        assert bool(addr) == \
            bool(data), "в непустой строке должены быть адрес и данные"

        if addr is None or data is None:
            return

        print(
            addr + ': ' + data,
            file=out_file
        )

    def process_column(x: int):
        y = MARGIN_TOP
        for i in range(ROWS):
            process_row(x, y)
            y += GLYPH_HEIGHT + LEADING

    x = MARGIN_LEFT
    while x < img.width:
        process_column(x)
        x += 128


if len(sys.argv) != 3:
    print('Использование: ./ocr.py ПУТЬ_PNG_ВАРИАНТА ПУТЬ_ВЫХОДНОГО_ФАЙЛА')
    sys.exit(1)

print("Программа прочитает файл с картинкой и распознает на ней текст\n")
print("Выведет программу в виде строк ADDR: DATA, это можно засунуть в ./disas.py -flab\n")
print("Точно подходит для 2 и 3 лабы\n")
print("Программа по ходу считывания будет спрашивать какому символу соотвествует неизвестный ей глиф\n")
print("Регистр букв не важен")
print("Главное не перепутать 8 и B!\n")

img = Image.open(sys.argv[1])

scan(img, open(sys.argv[2], 'w+'))

print(f'Текст записан в {sys.argv[2]}')
