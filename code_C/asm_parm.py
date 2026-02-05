#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Usage:
  python asm_parm.py input.s -o out.hex

Test (l'exemple du sujet):
  python asm_parm.py --selftest
"""

from __future__ import annotations
import argparse
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# ----------------------------
# Exceptions
# ----------------------------

class AsmError(Exception):
    def __init__(self, message: str, line_no: Optional[int] = None, line: Optional[str] = None):
        if line_no is not None:
            message = f"[L{line_no}] {message}"
        if line is not None:
            message = f"{message}\n    >> {line}"
        super().__init__(message)

# ----------------------------
# Parsing helpers
# ----------------------------

REG_ALIASES = {
    "sp": 13,
    "lr": 14,
    "pc": 15,
}

COND_CODES = {
    "eq": 0x0, "ne": 0x1,
    "cs": 0x2, "hs": 0x2,
    "cc": 0x3, "lo": 0x3,
    "mi": 0x4, "pl": 0x5,
    "vs": 0x6, "vc": 0x7,
    "hi": 0x8, "ls": 0x9,
    "ge": 0xA, "lt": 0xB,
    "gt": 0xC, "le": 0xD,
    "al": 0xE,   # utilisé par votre doc (BAL)
}

def parse_reg(tok: str) -> int:
    t = tok.strip().lower()
    if t in REG_ALIASES:
        return REG_ALIASES[t]
    m = re.fullmatch(r"r(\d+)", t)
    if not m:
        raise ValueError(f"Registre invalide: {tok}")
    n = int(m.group(1))
    if not (0 <= n <= 15):
        raise ValueError(f"Registre hors bornes: {tok}")
    return n

def parse_imm(tok: str) -> int:
    t = tok.strip().lower()
    if not t.startswith("#"):
        raise ValueError(f"Immédiat invalide: {tok}")
    t = t[1:].strip()
    if t.startswith("-0x"):
        return -int(t[3:], 16)
    if t.startswith("0x"):
        return int(t[2:], 16)
    return int(t, 10)

def split_operands(s: str) -> List[str]:
    """Split par virgules, sans casser l'intérieur des crochets [ ... ]."""
    ops = []
    cur = []
    depth = 0
    for ch in s:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            op = "".join(cur).strip()
            if op:
                ops.append(op)
            cur = []
        else:
            cur.append(ch)
    last = "".join(cur).strip()
    if last:
        ops.append(last)
    return ops

def parse_mem(op: str) -> Tuple[int, int]:
    """Parse: [Rn] ou [Rn, #imm] -> (Rn, imm)"""
    t = op.strip()
    if not (t.startswith("[") and t.endswith("]")):
        raise ValueError("Opérande mémoire invalide")
    inside = t[1:-1].strip()
    parts = split_operands(inside)
    if len(parts) == 0:
        raise ValueError("Adresse mémoire vide")
    rn = parse_reg(parts[0])
    imm = 0
    if len(parts) >= 2:
        imm = parse_imm(parts[1])
    if len(parts) > 2:
        raise ValueError("Trop d'arguments dans []")
    return rn, imm

def to_u16(x: int) -> int:
    return x & 0xFFFF

def fmt_hex16(x: int) -> str:
    return f"{x & 0xFFFF:04x}"

# ----------------------------
# Internal representation
# ----------------------------

@dataclass
class Instr:
    line_no: int
    text: str
    label: Optional[str]
    mnemonic: Optional[str]
    ops: List[str]
    pc_index: int  # index d'instruction (chaque instruction = 1 mot 16-bit)

# ----------------------------
# Encoder helpers
# ----------------------------

def check_bits_unsigned(val: int, bits: int, what: str):
    if not (0 <= val <= (1 << bits) - 1):
        raise AsmError(f"{what} hors bornes ({bits} bits): {val}")

def check_bits_signed(val: int, bits: int, what: str):
    mn = -(1 << (bits - 1))
    mx = (1 << (bits - 1)) - 1
    if not (mn <= val <= mx):
        raise AsmError(f"{what} hors bornes (signed {bits} bits): {val}")

def check_reg_low(r: int, what: str):
    if not (0 <= r <= 7):
        raise AsmError(f"{what} doit être entre r0 et r7 (Thumb16): r{r}")

# ----------------------------
# Encoders (Thumb-1 / subset PARM)
# ----------------------------

# Shift (immediate): 000xx imm5 Rm Rd
def encode_lsl_imm(rd: int, rm: int, imm5: int) -> int:
    check_reg_low(rd, "Rd")
    check_reg_low(rm, "Rm")
    check_bits_unsigned(imm5, 5, "imm5")
    return 0x0000 | (imm5 << 6) | (rm << 3) | rd

def encode_lsr_imm(rd: int, rm: int, imm5: int) -> int:
    check_reg_low(rd, "Rd")
    check_reg_low(rm, "Rm")
    check_bits_unsigned(imm5, 5, "imm5")
    return 0x0800 | (imm5 << 6) | (rm << 3) | rd

def encode_asr_imm(rd: int, rm: int, imm5: int) -> int:
    check_reg_low(rd, "Rd")
    check_reg_low(rm, "Rm")
    check_bits_unsigned(imm5, 5, "imm5")
    return 0x1000 | (imm5 << 6) | (rm << 3) | rd

def encode_movs_imm(rd: int, imm8: int) -> int:
    check_reg_low(rd, "Rd")
    check_bits_unsigned(imm8, 8, "imm8")
    return 0x2000 | (rd << 8) | imm8

def encode_cmp_imm(rn: int, imm8: int) -> int:
    check_reg_low(rn, "Rn")
    check_bits_unsigned(imm8, 8, "imm8")
    return 0x2800 | (rn << 8) | imm8

def encode_adds_imm8(rdn: int, imm8: int) -> int:
    check_reg_low(rdn, "Rdn")
    check_bits_unsigned(imm8, 8, "imm8")
    return 0x3000 | (rdn << 8) | imm8

def encode_subs_imm8(rdn: int, imm8: int) -> int:
    check_reg_low(rdn, "Rdn")
    check_bits_unsigned(imm8, 8, "imm8")
    return 0x3800 | (rdn << 8) | imm8

def encode_adds_reg(rd: int, rn: int, rm: int) -> int:
    # 0001100 Rm Rn Rd
    check_reg_low(rd, "Rd")
    check_reg_low(rn, "Rn")
    check_reg_low(rm, "Rm")
    return 0x1800 | (rm << 6) | (rn << 3) | rd

def encode_subs_reg(rd: int, rn: int, rm: int) -> int:
    # 0001101 Rm Rn Rd
    check_reg_low(rd, "Rd")
    check_reg_low(rn, "Rn")
    check_reg_low(rm, "Rm")
    return 0x1A00 | (rm << 6) | (rn << 3) | rd

def encode_adds_imm3(rd: int, rn: int, imm3: int) -> int:
    # 0001110 imm3 Rn Rd
    check_reg_low(rd, "Rd")
    check_reg_low(rn, "Rn")
    check_bits_unsigned(imm3, 3, "imm3")
    return 0x1C00 | (imm3 << 6) | (rn << 3) | rd

def encode_subs_imm3(rd: int, rn: int, imm3: int) -> int:
    # 0001111 imm3 Rn Rd
    check_reg_low(rd, "Rd")
    check_reg_low(rn, "Rn")
    check_bits_unsigned(imm3, 3, "imm3")
    return 0x1E00 | (imm3 << 6) | (rn << 3) | rd

# Data Processing: 010000 opcode Rm Rdn
def encode_dp(opcode: int, rdn: int, rm: int) -> int:
    check_bits_unsigned(opcode, 4, "opcode")
    check_reg_low(rdn, "Rdn")
    check_reg_low(rm, "Rm")
    return 0x4000 | (opcode << 6) | (rm << 3) | rdn

# Load/Store SP-relative (word)
def encode_str_sp(rt: int, imm: int) -> int:
    if imm % 4 != 0:
        raise AsmError("Offset STR [sp, #imm] doit être multiple de 4")
    rt = int(rt)
    check_reg_low(rt, "Rt")
    imm8 = imm // 4
    check_bits_unsigned(imm8, 8, "imm8")
    return 0x9000 | (rt << 8) | imm8

def encode_ldr_sp(rt: int, imm: int) -> int:
    if imm % 4 != 0:
        raise AsmError("Offset LDR [sp, #imm] doit être multiple de 4")
    rt = int(rt)
    check_reg_low(rt, "Rt")
    imm8 = imm // 4
    check_bits_unsigned(imm8, 8, "imm8")
    return 0x9800 | (rt << 8) | imm8

# Load/Store base register (word) : 0110 x imm5 Rn Rt
def encode_str_imm_word(rt: int, rn: int, imm: int) -> int:
    if imm % 4 != 0:
        raise AsmError("Offset STR [Rn, #imm] (word) doit être multiple de 4")
    check_reg_low(rt, "Rt")
    check_reg_low(rn, "Rn")
    imm5 = imm // 4
    check_bits_unsigned(imm5, 5, "imm5")
    return 0x6000 | (imm5 << 6) | (rn << 3) | rt

def encode_ldr_imm_word(rt: int, rn: int, imm: int) -> int:
    if imm % 4 != 0:
        raise AsmError("Offset LDR [Rn, #imm] (word) doit être multiple de 4")
    check_reg_low(rt, "Rt")
    check_reg_low(rn, "Rn")
    imm5 = imm // 4
    check_bits_unsigned(imm5, 5, "imm5")
    return 0x6800 | (imm5 << 6) | (rn << 3) | rt

# Byte variants
def encode_strb_imm(rt: int, rn: int, imm: int) -> int:
    check_reg_low(rt, "Rt")
    check_reg_low(rn, "Rn")
    check_bits_unsigned(imm, 5, "imm5")
    return 0x7000 | (imm << 6) | (rn << 3) | rt

def encode_ldrb_imm(rt: int, rn: int, imm: int) -> int:
    check_reg_low(rt, "Rt")
    check_reg_low(rn, "Rn")
    check_bits_unsigned(imm, 5, "imm5")
    return 0x7800 | (imm << 6) | (rn << 3) | rt

# SP adjust
def encode_add_sp_imm(imm: int) -> int:
    if imm % 4 != 0:
        raise AsmError("ADD sp, #imm : imm doit être multiple de 4")
    imm7 = imm // 4
    check_bits_unsigned(imm7, 7, "imm7")
    return 0xB000 | imm7

def encode_sub_sp_imm(imm: int) -> int:
    if imm % 4 != 0:
        raise AsmError("SUB sp, #imm : imm doit être multiple de 4")
    imm7 = imm // 4
    check_bits_unsigned(imm7, 7, "imm7")
    return 0xB080 | imm7

def encode_add_rd_sp_imm(rd: int, imm: int) -> int:
    if imm % 4 != 0:
        raise AsmError("ADD Rd, sp, #imm : imm doit être multiple de 4")
    check_reg_low(rd, "Rd")
    imm8 = imm // 4
    check_bits_unsigned(imm8, 8, "imm8")
    return 0xA000 | (rd << 8) | imm8

# Branches
def encode_b_uncond(cur_pc_index: int, target_pc_index: int) -> int:
    rel = target_pc_index - (cur_pc_index + 2)
    check_bits_signed(rel, 11, "offset (B)")
    return 0xE000 | (rel & 0x7FF)

def encode_b_cond(cond: int, cur_pc_index: int, target_pc_index: int) -> int:
    rel = target_pc_index - (cur_pc_index + 2)
    check_bits_signed(rel, 8, "offset (B<cond>)")
    return 0xD000 | (cond << 8) | (rel & 0xFF)

def encode_bx(rm: int) -> int:
    # BX Rm: 010001 11 0 Rm 000
    return 0x4700 | (rm << 3)

def encode_nop() -> int:
    return 0xBF00

# ----------------------------
# Assembler core
# ----------------------------

def preprocess_lines(src: str) -> List[Tuple[int, str]]:
    out = []
    for i, raw in enumerate(src.splitlines(), start=1):
        line = raw.split("@", 1)[0].rstrip()
        line = line.strip()
        if not line:
            continue
        if line.startswith(".") and ":" not in line:
            continue
        out.append((i, line))
    return out

def parse_instructions(lines: List[Tuple[int, str]]) -> List[Instr]:
    instrs: List[Instr] = []
    pc = 0
    for line_no, line in lines:
        original = line

        label = None
        if ":" in line:
            before, after = line.split(":", 1)
            if before.strip():
                label = before.strip()
                line = after.strip()
                if not line:
                    instrs.append(Instr(line_no, original, label, None, [], pc))
                    continue

        parts = line.split(None, 1)
        mnemonic = parts[0].lower()
        ops_str = parts[1].strip() if len(parts) == 2 else ""
        ops = split_operands(ops_str) if ops_str else []

        # ignore push/pop (prologue/épilogue C)
        if mnemonic in ("push", "pop"):
            instrs.append(Instr(line_no, original, label, None, [], pc))
            continue

        # ignore "add r7, sp, ..." (prologue C)
        if mnemonic == "add" and len(ops) >= 2:
            try:
                if parse_reg(ops[0]) == 7 and parse_reg(ops[1]) == 13:
                    instrs.append(Instr(line_no, original, label, None, [], pc))
                    continue
            except Exception:
                pass

        instrs.append(Instr(line_no, original, label, mnemonic, ops, pc))
        pc += 1

    return instrs

def build_symbol_table(instrs: List[Instr]) -> Dict[str, int]:
    sym: Dict[str, int] = {}
    for ins in instrs:
        if ins.label:
            if ins.label in sym:
                raise AsmError(f"Label dupliqué: {ins.label}", ins.line_no, ins.text)
            sym[ins.label] = ins.pc_index
    return sym

def _dp_two_or_three_operands(ins: Instr) -> Tuple[int, int]:
    """
    Thumb-1 DP = forme 2 opérandes: OP Rdn, Rm
    Tolérance: forme 3 opérandes OP Rd, Rn, Rm seulement si Rd == Rn
    """
    ops = ins.ops
    if len(ops) == 2:
        rdn = parse_reg(ops[0]); rm = parse_reg(ops[1])
        return rdn, rm
    if len(ops) == 3:
        rd = parse_reg(ops[0]); rn = parse_reg(ops[1]); rm = parse_reg(ops[2])
        if rd != rn:
            raise AsmError("Forme 3 opérandes supportée seulement si Rd == Rn (Thumb16)", ins.line_no, ins.text)
        return rd, rm
    raise AsmError("Attend 2 (ou 3 si Rd==Rn) opérandes", ins.line_no, ins.text)

def encode_one(ins: Instr, sym: Dict[str, int]) -> Optional[int]:
    if ins.mnemonic is None:
        return None

    m = ins.mnemonic
    ops = ins.ops

    # Aliases sans 's'
    ALIAS = {
        "and": "ands",
        "eor": "eors",
        "orr": "orrs",
        "adc": "adcs",
        "sbc": "sbcs",
        "ror": "rors",
        "bic": "bics",
        "mvn": "mvns",
        "mul": "muls",
        "lsl": "lsls",
        "lsr": "lsrs",
        "asr": "asrs",
    }
    m = ALIAS.get(m, m)

    try:
        # NOP / BX
        if m == "nop":
            return encode_nop()

        if m == "bx":
            if len(ops) != 1:
                raise AsmError("bx attend 1 opérande", ins.line_no, ins.text)
            rm = parse_reg(ops[0])
            return encode_bx(rm)

        # ----------------------------
        # Shift (imm5) ou Shift (reg DP)
        # ----------------------------
        if m in ("lsls", "lsrs", "asrs"):
            if len(ops) == 3:
                rd = parse_reg(ops[0])
                rm = parse_reg(ops[1])
                imm = parse_imm(ops[2])
                if imm < 0:
                    raise AsmError(f"{m} imm5 ne supporte pas les négatifs", ins.line_no, ins.text)
                if m == "lsls":
                    return encode_lsl_imm(rd, rm, imm)
                if m == "lsrs":
                    return encode_lsr_imm(rd, rm, imm)
                return encode_asr_imm(rd, rm, imm)

            if len(ops) == 2:
                rdn, rm = _dp_two_or_three_operands(ins)  # ici ça gère 2 ops
                opcode = {"lsls": 0x2, "lsrs": 0x3, "asrs": 0x4}[m]
                return encode_dp(opcode, rdn, rm)

            raise AsmError(f"{m} attend 2 (reg) ou 3 (imm5) opérandes", ins.line_no, ins.text)

        # ----------------------------
        # MOVS imm8
        # ----------------------------
        if m == "movs":
            if len(ops) != 2:
                raise AsmError("movs attend 2 opérandes: Rd, #imm8", ins.line_no, ins.text)
            rd = parse_reg(ops[0])
            if ops[1].strip().startswith("#"):
                imm = parse_imm(ops[1])
                if imm < 0:
                    raise AsmError("movs imm8 ne supporte pas les négatifs", ins.line_no, ins.text)
                return encode_movs_imm(rd, imm)
            raise AsmError("movs supporte uniquement: movs Rd, #imm8", ins.line_no, ins.text)

        # ----------------------------
        # ADDS / SUBS (imm8 | reg | imm3)
        # ----------------------------
        if m in ("adds", "subs"):
            if len(ops) == 2:
                rdn = parse_reg(ops[0])
                imm = parse_imm(ops[1])
                if imm < 0:
                    raise AsmError(f"{m} imm ne supporte pas les négatifs", ins.line_no, ins.text)
                return encode_adds_imm8(rdn, imm) if m == "adds" else encode_subs_imm8(rdn, imm)

            if len(ops) == 3:
                rd = parse_reg(ops[0])
                rn = parse_reg(ops[1])

                if ops[2].strip().startswith("#"):
                    imm3 = parse_imm(ops[2])
                    if imm3 < 0:
                        raise AsmError(f"{m} imm3 ne supporte pas les négatifs", ins.line_no, ins.text)
                    return encode_adds_imm3(rd, rn, imm3) if m == "adds" else encode_subs_imm3(rd, rn, imm3)

                rm = parse_reg(ops[2])
                return encode_adds_reg(rd, rn, rm) if m == "adds" else encode_subs_reg(rd, rn, rm)

            raise AsmError(f"{m} attend 2 ou 3 opérandes", ins.line_no, ins.text)

        # ----------------------------
        # CMP (imm8 ou reg)
        # ----------------------------
        if m == "cmp":
            if len(ops) != 2:
                raise AsmError("cmp attend 2 opérandes", ins.line_no, ins.text)
            rn = parse_reg(ops[0])
            if ops[1].strip().startswith("#"):
                imm = parse_imm(ops[1])
                if imm < 0:
                    raise AsmError("cmp imm8 ne supporte pas les négatifs", ins.line_no, ins.text)
                return encode_cmp_imm(rn, imm)
            rm = parse_reg(ops[1])
            return encode_dp(0xA, rn, rm)  # CMP reg

        # ----------------------------
        # Data Processing (16 ops)
        # ----------------------------
        DP_OPCODES = {
            "ands": 0x0,
            "eors": 0x1,
            "adcs": 0x5,
            "sbcs": 0x6,
            "rors": 0x7,
            "tst":  0x8,
            "rsbs": 0x9,
            "cmn":  0xB,
            "orrs": 0xC,
            "muls": 0xD,
            "bics": 0xE,
            "mvns": 0xF,
        }
        if m in DP_OPCODES:
            if m in ("tst", "rsbs", "cmn"):
                if len(ops) != 2:
                    raise AsmError(f"{m} attend 2 opérandes", ins.line_no, ins.text)
                rdn = parse_reg(ops[0]); rm = parse_reg(ops[1])
                return encode_dp(DP_OPCODES[m], rdn, rm)

            rdn, rm = _dp_two_or_three_operands(ins)
            return encode_dp(DP_OPCODES[m], rdn, rm)

        # ----------------------------
        # LDR/STR (SP relative / base reg / byte)
        # ----------------------------
        if m in ("ldr", "str", "ldrb", "strb"):
            if len(ops) != 2:
                raise AsmError(f"{m} attend 2 opérandes", ins.line_no, ins.text)
            rt = parse_reg(ops[0])
            rn, imm = parse_mem(ops[1])

            if rn == 13 and m in ("ldr", "str"):
                if imm < 0:
                    raise AsmError("Offset [sp,#imm] négatif non supporté ici", ins.line_no, ins.text)
                return encode_ldr_sp(rt, imm) if m == "ldr" else encode_str_sp(rt, imm)

            if imm < 0:
                raise AsmError("Offset négatif non supporté", ins.line_no, ins.text)

            if m == "ldr":
                return encode_ldr_imm_word(rt, rn, imm)
            if m == "str":
                return encode_str_imm_word(rt, rn, imm)
            if m == "ldrb":
                return encode_ldrb_imm(rt, rn, imm)
            if m == "strb":
                return encode_strb_imm(rt, rn, imm)

        # ----------------------------
        # ADD/SUB SP (misc)
        # ----------------------------
        if m == "add":
            if len(ops) == 2 and ops[0].strip().lower() == "sp" and ops[1].strip().startswith("#"):
                imm = parse_imm(ops[1])
                if imm < 0:
                    raise AsmError("add sp,#imm négatif -> utiliser sub", ins.line_no, ins.text)
                return encode_add_sp_imm(imm)

            if len(ops) == 3 and ops[1].strip().lower() == "sp" and ops[2].strip().startswith("#"):
                rd = parse_reg(ops[0])
                imm = parse_imm(ops[2])
                if imm < 0:
                    raise AsmError("add Rd,sp,#imm négatif non supporté ici", ins.line_no, ins.text)
                return encode_add_rd_sp_imm(rd, imm)

            raise AsmError("add supporté uniquement: add sp,#imm ou add Rd,sp,#imm", ins.line_no, ins.text)

        if m == "sub":
            if len(ops) == 2 and ops[0].strip().lower() == "sp" and ops[1].strip().startswith("#"):
                imm = parse_imm(ops[1])
                if imm < 0:
                    raise AsmError("sub sp,#imm négatif -> utiliser add", ins.line_no, ins.text)
                return encode_sub_sp_imm(imm)
            raise AsmError("sub supporté uniquement: sub sp,#imm", ins.line_no, ins.text)

        # ----------------------------
        # Branches (après DP pour éviter conflit avec BIC)
        # ----------------------------
        if m == "b":
            if len(ops) != 1:
                raise AsmError("b attend 1 opérande (label)", ins.line_no, ins.text)
            label = ops[0].strip()
            if label not in sym:
                raise AsmError(f"Label inconnu: {label}", ins.line_no, ins.text)
            return encode_b_uncond(ins.pc_index, sym[label])

        if m.startswith("b") and len(m) == 3 and (m[1:] in COND_CODES):
            if len(ops) != 1:
                raise AsmError(f"{m} attend 1 opérande (label)", ins.line_no, ins.text)
            label = ops[0].strip()
            if label not in sym:
                raise AsmError(f"Label inconnu: {label}", ins.line_no, ins.text)
            return encode_b_cond(COND_CODES[m[1:]], ins.pc_index, sym[label])

        raise AsmError(f"Instruction non supportée: {m}", ins.line_no, ins.text)

    except AsmError:
        raise
    except Exception as e:
        raise AsmError(str(e), ins.line_no, ins.text)

def assemble_text(src: str) -> List[int]:
    lines = preprocess_lines(src)
    instrs = parse_instructions(lines)
    sym = build_symbol_table(instrs)

    out: List[int] = []
    for ins in instrs:
        code = encode_one(ins, sym)
        if code is not None:
            out.append(to_u16(code))
    return out

def write_logisim_hex(words: List[int], path: str, wrap: int = 16):
    with open(path, "w", encoding="utf-8") as f:
        f.write("v2.0 raw\n")
        for i, w in enumerate(words):
            if i > 0:
                if wrap > 0 and i % wrap == 0:
                    f.write("\n")
                else:
                    f.write(" ")
            f.write(fmt_hex16(w))
        f.write("\n")

# ----------------------------
# Self-test (exemple du sujet)
# ----------------------------

SELFTEST_S = r"""
sub sp, #12
movs r0, #0
str r0, [sp, #8]
movs r1, #1
str r1, [sp, #4]
ldr r1, [sp, #8]
ldr r2, [sp, #4]
adds r1, r1, r2
str r1, [sp]
add sp, #12
"""

SELFTEST_EXPECT = "b083 2000 9002 2101 9101 9902 9a01 1889 9100 b003"

def run_selftest():
    words = assemble_text(SELFTEST_S)
    got = " ".join(fmt_hex16(w) for w in words)
    if got != SELFTEST_EXPECT:
        raise SystemExit(f"SELFTEST FAIL\ngot : {got}\nwant: {SELFTEST_EXPECT}")
    print("SELFTEST OK")
    print("v2.0 raw")
    print(got)

# ----------------------------
# CLI
# ----------------------------

def main():
    ap = argparse.ArgumentParser(description="Assembleur Thumb16 -> Logisim v2.0 raw")
    ap.add_argument("input", nargs="?", help="fichier assembleur .s")
    ap.add_argument("-o", "--output", help="fichier sortie .hex (Logisim)", default="out.hex")
    ap.add_argument("--wrap", type=int, default=16, help="nb de mots par ligne (0=pas de wrap)")
    ap.add_argument("--selftest", action="store_true", help="lance le test de l'exemple du sujet")
    args = ap.parse_args()

    if args.selftest:
        run_selftest()
        return

    if not args.input:
        raise SystemExit("Erreur: il faut un fichier .s (ou utiliser --selftest)")

    with open(args.input, "r", encoding="utf-8") as f:
        src = f.read()

    words = assemble_text(src)
    write_logisim_hex(words, args.output, wrap=args.wrap)
    print(f"OK: {len(words)} instructions -> {args.output}")

if __name__ == "__main__":
    main()
