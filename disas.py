#!/usr/bin/env python3

import argparse
import sys
import re

from dataclasses import dataclass
from bisect import bisect_left
from typing import cast
from enum import Enum
from copy import copy


@dataclass
class Instr:
    mnemonic: str
    word: int


class IllegalInstr(Instr):
    def __init__(self, word: int):
        super().__init__('ILLEGAL', word)


@dataclass
class ImplInstr(Instr):
    """ Безадресная команда """
    pass


@dataclass
class IOInstr(Instr):
    opnd: int


@dataclass
class AddrOrImmInstr(Instr):
    """
    Инструкция с прямой абсолютной/относительной адресацией или с прямой загрузкой операнда.
    К ним также относятся JUMP и Bxx.
    """

    class Mode(Enum):
        # * IP, SP - регистры,
        # * [X] - значени ячейки памяти с адресом X,
        # * OPND - 8-битный операнд (если не указано иное), дополненный нулями до 11/16 бит
        #   (в зависимости от контекста).

        IMMEDIATE = 0
        """ Непосредственная: OPND """
        ABSOLUTE_DIRECT = 1
        """ Абсолютная прямая: (OPND - 11 бит): [OPND] """
        IP_RELATIVE_DIRECT = 2
        """ Относительная IP прямая: [IP + OPND] """
        IP_RELATIVE_INDIRECT = 3
        """ Относительная косвенная: [[IP + OPND]] """
        IP_RELATIVE_INDIRECT_INC = 4
        """ 
        Относительная косвенная с постинкрементом: [[IP + OPND]]
        После загрузки [IP+OPND] увеличивается на 1
        """
        IP_RELATIVE_INDIRECT_DEC = 5
        """ 
        Относительная косвенная с постдекрементом: [[IP + OPND]]
        После загрузки [IP+OPND] уменьшается на 1
        """
        SP_RELATIVE_DIRECT = 6
        """ Относительная SP прямая: [SP + OPND] """

    mode: Mode
    opnd: int
    """
    Если режим не IMMEDIATE и SP_RELATIVE_DIRECT, то содержит абсолютный адрес.
    """


def disas_instr(cur_addr: int, word: int) -> tuple[Instr, int | None]:
    """
    @return: дизассемблированная команда и абсолютный адрес, к которому обращается команда
        (если есть).
    """
    opcode = (word & 0xF000) >> 12
    other = word & 0x0FFF

    def ip_rel_to_abs(offset: int) -> int:
        if offset < 128:
            return cur_addr + offset + 1
        else:
            return cur_addr - (256 - offset) + 1

    def impl() -> tuple[ImplInstr, None] | None:
        mnemonics = {
            0x000: 'NOP',
            0x100: 'HLT',
            0x200: 'CLA',
            0x280: 'NOT',
            0x300: 'CLC',
            0x380: 'CMC',
            0x400: 'ROL',
            0x480: 'ROR',
            0x500: 'ASL',
            0x580: 'ASR',
            0x600: 'SXTB',
            0x680: 'SWAB',
            0x700: 'INC',
            0x740: 'DEC',
            0x780: 'NEG',
            0x800: 'POP',
            0x900: 'POPF',
            0xA00: 'RET',
            0xB00: 'IRET',
            0xC00: 'PUSH',
            0xD00: 'PUSHF',
            0xE00: 'SWAP',
        }

        if other not in mnemonics:
            return None

        return ImplInstr(mnemonics[other], word), None

    def io() -> tuple[IOInstr, None] | None:
        mnemonics = {
            0x0: 'DI',
            0x1: 'EI',
            0x2: 'IN',
            0x3: 'OUT',
            0x8: 'INT'
        }
        ext_opcode = (other & 0b111100000000) >> 8
        if ext_opcode not in mnemonics:
            return None

        return IOInstr(mnemonics[ext_opcode], word, other & 0b000011111111), None

    def addr_or_imm() -> tuple[AddrOrImmInstr, int | None] | None:
        bit11 = (other & 0b100000000000) >> 11

        mnemonics = {
            0x2: 'AND',
            0x3: 'OR',
            0x4: 'ADD',
            0x5: 'ADC',
            0x6: 'SUB',
            0x7: 'CMP',
            0x8: 'LOOP',
            # 0x9 reserved
            0xA: 'LD',
            0xB: 'SWAM',
            0xC: 'JUMP',
            0xD: 'CALL',
            0xE: 'ST',
        }

        if opcode not in mnemonics:
            return None

        mnemonic = mnemonics[opcode]

        if bit11:
            mode_bits = (other & 0b011100000000) >> 8
            opnd = other & 0b000011111111
            modes = {
                0b111: AddrOrImmInstr.Mode.IMMEDIATE,
                0b110: AddrOrImmInstr.Mode.IP_RELATIVE_DIRECT,
                0b000: AddrOrImmInstr.Mode.IP_RELATIVE_INDIRECT,
                0b010: AddrOrImmInstr.Mode.IP_RELATIVE_INDIRECT_INC,
                0b011: AddrOrImmInstr.Mode.IP_RELATIVE_INDIRECT_DEC,
                0b100: AddrOrImmInstr.Mode.SP_RELATIVE_DIRECT,
            }

            if mode_bits not in modes:
                return None

            mode = modes[mode_bits]
            if mode not in [
                AddrOrImmInstr.Mode.IMMEDIATE,
                AddrOrImmInstr.Mode.SP_RELATIVE_DIRECT
            ]:
                addr = ip_rel_to_abs(opnd)
                return AddrOrImmInstr(mnemonic, word, mode, addr), addr
            else:
                return AddrOrImmInstr(mnemonic, word, mode, opnd), None

        else:
            addr = other & 0b011111111111
            return AddrOrImmInstr(
                mnemonic,
                word,
                AddrOrImmInstr.Mode.ABSOLUTE_DIRECT,
                addr
            ), addr

    def branch() -> tuple[AddrOrImmInstr, int] | None:
        ext_opcode = (other & 0b111100000000) >> 8
        mnemonics = {
            0: 'BEQ',
            1: 'BNE',
            2: 'BMI',
            3: 'BPL',
            4: 'BHIS',
            5: 'BLO',
            6: 'BVS',
            7: 'BVC',
            8: 'BLT',
            9: 'BGE'
        }

        if ext_opcode not in mnemonics:
            return None

        offset = other & 0b000011111111
        addr = ip_rel_to_abs(offset)

        return AddrOrImmInstr(
            mnemonics[ext_opcode],
            word,
            AddrOrImmInstr.Mode.IP_RELATIVE_DIRECT,
            addr
        ), addr

    match opcode:
        case 0b0000:
            instr = impl()
        case 0b0001:
            instr = io()
        case 0b1111:
            instr = branch()
        case _:
            instr = addr_or_imm()

    if instr is None:
        return IllegalInstr(word), None

    return instr


def dump_prog(
    addrs_and_instrs: list[tuple[int, Instr]],
    accessed_addrs: list[int],
    show_addrs_for_instrs=False,
    show_instr_bin_repr=False,
    russian=False
) -> str:
    lines = []
    last_addr = -2
    label_cnt = 0
    addrs_and_instrs_copy = copy(addrs_and_instrs)
    accessed_addrs_copy = copy(accessed_addrs)

    EN_TO_RU = {
        'AND': 'И',
        'OR': 'ИЛИ',
        'ADD': 'ПЛЮС',
        'ADC': 'ПЛЮСС',
        'SUB': 'МИНУС',
        'CMP': 'ЧЁ',
        'LOOP': 'КРУГ',
        'LD': 'НЯМ',
        'SWAM': 'ОБМЕН',
        'JUMP': 'ПРЫГ',
        'CALL': 'ВЖУХ',
        'ST': 'ТЬФУ',
        'NOP': 'ПРОП',
        'HLT': 'СТОП',
        'CLA': 'ЧИСТЬ',
        'NOT': 'НЕТЬ',
        'CLC': 'ЧИСТЦ',
        'CMC': 'ИНВЦ',
        'ROL': 'ЦЛЕВ',
        'ROR': 'ЦПРАВ',
        'ASL': 'АЛЕВ',
        'ASR': 'АПРАВ',
        'SXTB': 'ШЫРЬ',
        'SWAB': 'НАОБОРОТ',
        'INC': 'УВЕЛ',
        'DEC': 'УМЕН',
        'NEG': 'ОТРИЦ',
        'POP': 'ВЫНЬ',
        'POPF': 'ВЫНЬФ',
        'RET': 'ВЗАД',
        'IRET': 'ВЗАДП',
        'PUSH': 'СУНЬ',
        'PUSHF': 'СУНЬФ',
        'SWAP': 'МЕНЬ',
        'BEQ': 'БЯКА',
        'BNE': 'БНЕКА',
        'BMI': 'БМИНУС ',
        'BPL': 'БПЛЮС',
        'BHIS': 'БЕЦ',
        'BLO': 'БНЕЦ',
        'BVS': 'БОВЕР',
        'BVC': 'БНЕОВЕР',
        'BLT': 'БМЕНЬ',
        'BGE': 'БНЕМЕНЬ',
        'DI': 'НИЗЯ',
        'EI': 'ЛЬЗЯ',
        'IN': 'СЮДА',
        'OUT': 'ТУДА',
        'INT': 'ПРЕР',
        'ILLEGAL': 'ЧУШЬ',

        'IP': 'СК',
        'SP': 'УС',

        'ORG': 'НАЧ',
        'WORD': 'СЛОВО',
        'label': 'метка'
    }

    def trans(keyword: str) -> str:
        if russian:
            return EN_TO_RU[keyword]
        else:
            return keyword

    def place_org(addr: int):
        if addr is not None:
            lines.append(f'            {trans("ORG"):12}  0x{addr:03x}')

    def place_label(cnt: int, addr: int):
        nonlocal lines, last_addr

        if len(lines) != 0:
            lines.append('')

        if last_addr + 1 != addr:
            place_org(addr)

        lines.append(f'{trans("label")}{cnt}:')

        last_addr = addr - 1

    def addr_or_imm_opnd_to_str(instr: AddrOrImmInstr, instr_addr: int) -> str:
        def ip_rel_to_str(addr):
            if addr < instr_addr:
                return f'IP-{instr_addr - addr}'
            else:
                return f'IP+{addr - instr_addr}'

        match instr.mode:
            case AddrOrImmInstr.Mode.IMMEDIATE:
                return f' #0x{instr.opnd:02x}'

            case AddrOrImmInstr.Mode.SP_RELATIVE_DIRECT:
                return f' ({trans("SP")}+{instr.opnd})'

            case _:
                i = bisect_left(accessed_addrs, instr.opnd)
                assert accessed_addrs[i] == instr.opnd
                opnd_str = f'{trans("label")}{i}'

                ip_rel = ip_rel_to_str(instr.opnd)

                match instr.mode:
                    case AddrOrImmInstr.Mode.ABSOLUTE_DIRECT:
                        opnd_str = f' ${opnd_str}'
                        comm = ''
                    case AddrOrImmInstr.Mode.IP_RELATIVE_DIRECT:
                        opnd_str = f'  {opnd_str}'
                        comm = f';   {ip_rel}'
                        # return f'  {opnd_str:8}   ; {rel_str}'
                    case AddrOrImmInstr.Mode.IP_RELATIVE_INDIRECT:
                        opnd_str = f' ({opnd_str})'
                        comm = f';  ({ip_rel})'
                        # return f' ({opnd_str}:8)   ; ({rel_str})'
                    case AddrOrImmInstr.Mode.IP_RELATIVE_INDIRECT_INC:
                        opnd_str = f' ({opnd_str})+'
                        comm = f';  ({ip_rel})+'
                        # return f' ({opnd_str})+ ; ({rel_str})+'
                    case AddrOrImmInstr.Mode.IP_RELATIVE_INDIRECT_DEC:
                        opnd_str = f'-({opnd_str})'
                        comm = f'; -({ip_rel})'

                if not comm:
                    return opnd_str

                return f'{opnd_str:16}{comm}'

    def place_instr(instr: Instr, addr: int):
        nonlocal last_addr

        if last_addr + 1 != addr:
            place_org(addr)
            lines.append('')

        line = ''
        if show_addrs_for_instrs:
            line += f'{addr:03x}:'
        else:
            line += ' ' * 4

        if show_instr_bin_repr:
            line += f' {instr.word:04x}'
        else:
            line += ' ' * 5

        line += ' ' * 3

        tr_mnemonic = trans(instr.mnemonic)

        match instr:
            case ImplInstr():
                line += tr_mnemonic
            case IllegalInstr():
                line += f'{trans("WORD"):12}  0x{instr.word:04x}'
            case _:
                line += f'{tr_mnemonic:12}'

                match instr:
                    case IOInstr():
                        line += f'  0x{instr.opnd:02x}'
                    case AddrOrImmInstr():
                        line += addr_or_imm_opnd_to_str(instr, instr_addr)

        lines.append(line)
        last_addr = addr

    def place_labels(until_addr: int):
        nonlocal label_cnt

        while accessed_addrs_copy:
            if accessed_addrs_copy[0] > until_addr:
                break

            place_label(label_cnt, accessed_addrs_copy[0])
            label_cnt += 1

            del accessed_addrs_copy[0]

    while addrs_and_instrs_copy:
        instr_addr, instr = addrs_and_instrs_copy[0]

        place_labels(instr_addr)

        place_instr(instr, instr_addr)

        del addrs_and_instrs_copy[0]

    # все оставшиеся
    place_labels(2**11)

    return '\n'.join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='БЭВМ дизассемблер',
    )
    parser.add_argument(
        'filepath',
        help='Путь к файлу с кодом программы. Если не указать, то читается stdin',
        nargs='?',
        default=None
    )
    parser.add_argument(
        '-f', '--input-format',
        help='По умолчанию bin - программа в бинарном виде, hex - набор шестнадцатиричных цифр, '
        'которые могут быть разделены пробельными символами, lab - в формате варианта лабораторной '
        'РАБоты',
        nargs='?',
        default='bin'
    )
    parser.add_argument(
        '-o', '--org',
        help='Адрес, который в памяти БЭВМ имеет первое слово входных данных. По умолчанию 0x10. '
        'Не учитывается если --input-format lab',
    )
    parser.add_argument(
        '-a', '--addr',
        help='Добавить в выводе к каждой инструкции её адрес',
        action='store_true'
    )
    parser.add_argument(
        '-b', '--bin',
        help='Добавить в выводе к каждой инструкции её бинарное представление',
        action='store_true'
    )
    parser.add_argument(
        '-r', '--ru',
        help='Выводить мнемоники команд и названия меток на русском',
        action='store_true'
    )
    args = parser.parse_args()

    # Выбрать начальный адрес
    if args.org is not None:
        if args.org.startswith('0x'):
            start_addr = int(args.org, 16)
        else:
            start_addr = int(args.org)
    else:
        start_addr = 0x10

    # Выбрать нужный файл
    if args.filepath is not None:
        file = open(
            args.filepath,
            'r' + ('b' if args.input_format == 'bin' else '')
        )
    else:
        if args.input_format == 'bin':
            file = sys.stdin.buffer
        else:
            file = sys.stdin

    instrs_addrs: list[int] | range
    fast_used_addrs: set[int] | range

    # Считать в нужном формате
    match args.input_format:
        case 'bin':
            data = cast(bytes, file.read())
            instrs_addrs = range(start_addr, start_addr + len(data) // 2)
        case 'hex':
            text = cast(str, file.read())
            text = re.sub(r'\s', '', text)

            if len(text) & 1:
                raise ValueError(
                    "Количество шестнадцатеричных цифр должно быть чётным"
                )

            data = bytearray.fromhex(text)
            instrs_addrs = range(start_addr, start_addr + len(data) // 2)
        case 'lab':
            LINE_RE = re.compile(r'^([0-9a-fA-F]+)\s*:\s*([0-9a-fA-F]+)$')

            instrs_addrs = []
            instrs_addrs_set = set()
            data = bytearray()

            for i, line in enumerate(cast(str, file.read()).split('\n')):
                line = line.strip()
                if not line:
                    continue

                m = LINE_RE.match(line)
                if m is None:
                    raise ValueError(f'invalid line {i + 1}')

                addr = int(m.group(1), 16)
                instr = int(m.group(2), 16)

                if addr in instrs_addrs_set:
                    raise ValueError(
                        f'В строке {i + 1} адрес {hex(addr)} используется второй раз'
                    )

                instrs_addrs.append(addr)
                instrs_addrs_set.add(addr)

                data.append(instr // 256)
                data.append(instr % 256)
        case _:
            print(f'Неизвестный формат {args.input_format}', file=sys.stderr)
            exit(1)

    if len(data) & 1:
        raise ValueError(
            "Количество байтов должно быть чётно - БЭВМ работает с 16-битными словами"
        )

    if len(data) == 0:
        raise ValueError("На вход дана пустая программа")

    # Дизассемблировать инструкции
    addrs_and_instrs: list[tuple[int, Instr]] = []
    accessed_addrs: set[int] = set()
    for i in range(0, len(data) // 2):
        word_bytes = data[i * 2:(i + 1) * 2]
        word = word_bytes[0] * 256 + word_bytes[1]

        instr, accessed_addr = disas_instr(instrs_addrs[i], word)
        addrs_and_instrs.append((instrs_addrs[i], instr))
        if accessed_addr is not None:
            accessed_addrs.add(accessed_addr)

    # Вывести программу
    print(dump_prog(
        sorted(addrs_and_instrs),
        sorted(accessed_addrs),
        show_addrs_for_instrs=args.addr,
        show_instr_bin_repr=args.bin,
        russian=args.ru
    ))
