#!/usr/bin/env python3
from __future__ import annotations
import re
import sys
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional

# -------------------------
# Helpers parsing
# -------------------------

REG_RE = re.compile(r"^r([0-7])$")

COND_CODES = {
    "eq": 0b0000, "ne": 0b0001,
    "cs": 0b0010, "hs": 0b0010,
    "cc": 0b0011, "lo": 0b0011,
    "mi": 0b0100, "pl": 0b0101,
    "vs": 0b0110, "vc": 0b0111,
    "hi": 0b1000, "ls": 0b1001,
    "ge": 0b1010, "lt": 0b1011,
    "gt": 0b1100, "le": 0b1101,
    "al": 0b1110,
}

def parse_reg(tok: str) -> int:
    tok = tok.strip().lower()
    m = REG_RE.match(tok)
    if not m:
        raise ValueError(f"Registre invalide: {tok} (attendu r0..r7)")
    return int(m.group(1))

def parse_imm(tok: str) -> int:
    tok = tok.strip().lower()
    if not tok.startswith("#"):
        raise ValueError(f"Immédiat invalide: {tok} (attendu #123 ou #0xFF)")
    v = tok[1:]
    base = 16 if v.startswith("0x") else 10
    return int(v, base)

def twos_comp(value: int, bits: int) -> int:
    """Encode signed value into bits (two's complement)."""
    minv = -(1 << (bits - 1))
    maxv = (1 << (bits - 1)) - 1
    if value < minv or value > maxv:
        raise ValueError(f"Valeur {value} hors plage pour {bits} bits signés [{minv}..{maxv}]")
    if value < 0:
        value = (1 << bits) + value
    return value & ((1 << bits) - 1)

def ucheck(value: int, bits: int, what: str) -> int:
    maxv = (1 << bits) - 1
    if value < 0 or value > maxv:
        raise ValueError(f"{what}={value} hors plage (0..{maxv})")
    return value

def tokenize(line: str) -> List[str]:
    # Remove comments starting with @ (PARM doc) and also ';' (souvent utilisé)
    line = line.split("@", 1)[0]
    line = line.split(";", 1)[0]
    line = line.strip().lower()
    if not line:
        return []

    # ignore directives
    if line.startswith("."):
        return []

    # normalize punctuation
    line = line.replace(",", " ")
    line = line.replace("[", " [ ").replace("]", " ] ")
    line = re.sub(r"\s+", " ", line).strip()
    return line.split(" ")

# -------------------------
# Encoder (Thumb 16-bit subset PARM)
# -------------------------

def enc_shift_imm(op: str, rd: int, rn: int, imm5: int) -> int:
    imm5 = ucheck(imm5, 5, "imm5")
    if op == "lsls":
        opbits = 0b00000
    elif op == "lsrs":
        opbits = 0b00001
    elif op == "asrs":
        opbits = 0b00010
    else:
        raise ValueError(f"Shift imm inconnu: {op}")
    return (opbits << 11) | (imm5 << 6) | (rn << 3) | rd

def enc_addsub_reg(op: str, rd: int, rn: int, rm: int) -> int:
    if op == "adds":
        base = 0b0001100
    elif op == "subs":
        base = 0b0001101
    else:
        raise ValueError(f"Add/Sub reg inconnu: {op}")
    return (base << 9) | (rm << 6) | (rn << 3) | rd

def enc_addsub_imm3(op: str, rd: int, rn: int, imm3: int) -> int:
    imm3 = ucheck(imm3, 3, "imm3")
    if op == "adds":
        base = 0b0001110
    elif op == "subs":
        base = 0b0001111
    else:
        raise ValueError(f"Add/Sub imm3 inconnu: {op}")
    return (base << 9) | (imm3 << 6) | (rn << 3) | rd

def enc_mov_imm8(rd: int, imm8: int) -> int:
    imm8 = ucheck(imm8, 8, "imm8")
    return (0b00100 << 11) | (rd << 8) | imm8

def enc_cmp_imm8(rn: int, imm8: int) -> int:
    imm8 = ucheck(imm8, 8, "imm8")
    return (0b00101 << 11) | (rn << 8) | imm8

def enc_addsub_imm8(op: str, rdn: int, imm8: int) -> int:
    imm8 = ucheck(imm8, 8, "imm8")
    if op == "adds":
        top = 0b00110
    elif op == "subs":
        top = 0b00111
    else:
        raise ValueError(f"Add/Sub imm8 inconnu: {op}")
    return (top << 11) | (rdn << 8) | imm8

# Data Processing opcodes (bits 9..6 in 010000 xxxx)
DP_OP = {
    "ands": 0b0000,
    "eors": 0b0001,
    "lsls": 0b0010,  # register form
    "lsrs": 0b0011,
    "asrs": 0b0100,
    "adcs": 0b0101,
    "sbcs": 0b0110,
    "rors": 0b0111,
    "tst":  0b1000,
    "rsbs": 0b1001,
    "cmp":  0b1010,
    "cmn":  0b1011,
    "orrs": 0b1100,
    "muls": 0b1101,
    "bics": 0b1110,
    "mvns": 0b1111,
}

def enc_dp(op: str, rdn: int, rm_or_rn: int) -> int:
    # General pattern: 010000 opcode(4) Rm Rdn
    # BUT: TST/CMP/CMN use Rn in place of Rdn conceptually; encoding still puts Rn in low reg field.
    opcode = DP_OP.get(op)
    if opcode is None:
        raise ValueError(f"DataProcessing inconnu: {op}")
    return (0b010000 << 10) | (opcode << 6) | (rm_or_rn << 3) | rdn

def enc_rsbs(rd: int, rn: int) -> int:
    # RSBS Rd, Rn, #0  => 0100001001 Rn Rd
    return (0b010000 << 10) | (0b1001 << 6) | (rn << 3) | rd

def enc_tst_cmp_cmn(op: str, rn: int, rm: int) -> int:
    opcode = DP_OP[op]  # 1000/1010/1011
    return (0b010000 << 10) | (opcode << 6) | (rm << 3) | rn

def enc_ldr_str_sp(op: str, rt: int, imm8: int) -> int:
    imm8 = ucheck(imm8, 8, "imm8")
    # In PARM: STR: 10010 Rt imm8 ; LDR: 10011 Rt imm8 (imm8 = offset/4) :contentReference[oaicite:7]{index=7}
    if op == "str":
        top = 0b10010
    elif op == "ldr":
        top = 0b10011
    else:
        raise ValueError("LDR/STR SP attendu")
    return (top << 11) | (rt << 8) | imm8

def enc_addsub_sp(op: str, imm7: int) -> int:
    imm7 = ucheck(imm7, 7, "imm7")
    # ADD SP,#imm7 : 101100000 imm7 ; SUB SP,#imm7 : 101100001 imm7  (imm7 = offset/4) :contentReference[oaicite:8]{index=8}
    if op == "add":
        return (0b101100000 << 7) | imm7
    elif op == "sub":
        return (0b101100001 << 7) | imm7
    else:
        raise ValueError("ADD/SUB SP attendu")

def enc_b_cond(cond: str, imm8_signed: int) -> int:
    imm8 = twos_comp(imm8_signed, 8)
    return (0b1101 << 12) | (COND_CODES[cond] << 8) | imm8

def enc_b_uncond(imm11_signed: int) -> int:
    imm11 = twos_comp(imm11_signed, 11)
    return (0b11100 << 11) | imm11

# -------------------------
# Main assemble logic
# -------------------------

@dataclass
class SrcLine:
    original: str
    tokens: List[str]
    lineno: int

def read_lines(path: str) -> List[SrcLine]:
    out: List[SrcLine] = []
    with open(path, "r", encoding="utf-8") as f:
        for i, raw in enumerate(f, start=1):
            toks = tokenize(raw)
            out.append(SrcLine(original=raw.rstrip("\n"), tokens=toks, lineno=i))
    return out

def pass1_labels(lines: List[SrcLine]) -> Tuple[Dict[str, int], List[SrcLine]]:
    labels: Dict[str, int] = {}
    inst_lines: List[SrcLine] = []
    pc = 0
    for sl in lines:
        toks = sl.tokens
        if not toks:
            continue
        # label handling: "label:" possibly alone or before instruction
        while toks and toks[0].endswith(":"):
            lab = toks[0][:-1]
            if not lab:
                raise ValueError(f"Ligne {sl.lineno}: label vide")
            if lab in labels:
                raise ValueError(f"Ligne {sl.lineno}: label dupliqué '{lab}'")
            labels[lab] = pc
            toks = toks[1:]
        if not toks:
            continue
        inst_lines.append(SrcLine(sl.original, toks, sl.lineno))
        pc += 1
    return labels, inst_lines

def assemble_line(toks: List[str], pc: int, labels: Dict[str, int]) -> int:
    op = toks[0]

    # Branches: b<cond> label  OR  b label
    if op.startswith("b") and op != "bic" and op != "bics":
        if op == "b":
            if len(toks) != 2:
                raise ValueError("Syntaxe: b label")
            label = toks[1]
            if label not in labels:
                raise ValueError(f"Label inconnu: {label}")
            imm = labels[label] - pc - 3  # doc PARM :contentReference[oaicite:9]{index=9}
            return enc_b_uncond(imm)
        else:
            # conditional e.g. beq, bne, bhi...
            cond = op[1:]  # 'eq'
            if cond not in COND_CODES:
                raise ValueError(f"Condition inconnue: {cond}")
            if len(toks) != 2:
                raise ValueError(f"Syntaxe: b{cond} label")
            label = toks[1]
            if label not in labels:
                raise ValueError(f"Label inconnu: {label}")
            imm = labels[label] - pc - 3  # doc PARM :contentReference[oaicite:10]{index=10}
            return enc_b_cond(cond, imm)

    # MOVS Rd, #imm8
    if op == "movs":
        rd = parse_reg(toks[1])
        imm8 = parse_imm(toks[2])
        return enc_mov_imm8(rd, imm8)

    # CMP immediate: cmp rn, #imm8
    if op == "cmp" and len(toks) == 3 and toks[2].startswith("#"):
        rn = parse_reg(toks[1])
        imm8 = parse_imm(toks[2])
        return enc_cmp_imm8(rn, imm8)

    # Shift imm: lsls/lsrs/asrs rd rn #imm5
    if op in ("lsls", "lsrs", "asrs") and len(toks) == 4 and toks[3].startswith("#"):
        rd = parse_reg(toks[1])
        rn = parse_reg(toks[2])
        imm5 = parse_imm(toks[3])
        return enc_shift_imm(op, rd, rn, imm5)

    # ADD/SUB immediate forms:
    # adds rd rn #imm3  OR adds rdn #imm8
    if op in ("adds", "subs"):
        if len(toks) == 4 and toks[3].startswith("#"):
            rd = parse_reg(toks[1])
            rn = parse_reg(toks[2])
            imm = parse_imm(toks[3])
            # choose imm3 vs imm8 based on syntax: if rd!=rn? still valid imm3 form. We'll decide by range+form.
            if imm <= 7:
                return enc_addsub_imm3(op, rd, rn, imm)
            raise ValueError(f"{op} imm3: imm doit être 0..7 (reçu {imm})")
        if len(toks) == 3 and toks[2].startswith("#"):
            rdn = parse_reg(toks[1])
            imm8 = parse_imm(toks[2])
            return enc_addsub_imm8(op, rdn, imm8)
        if len(toks) == 4:
            # adds rd rn rm
            rd = parse_reg(toks[1])
            rn = parse_reg(toks[2])
            rm = parse_reg(toks[3])
            return enc_addsub_reg(op, rd, rn, rm)

    # Data Processing:
    # ands rdn rm, eors rdn rm, ...
    if op in DP_OP:
        # Special cases with different operand semantics
        if op == "rsbs":
            # rsbs rd, rn, #0  (accept rsbs rd rn)
            rd = parse_reg(toks[1])
            rn = parse_reg(toks[2])
            return enc_rsbs(rd, rn)
        if op in ("tst", "cmp", "cmn") and len(toks) == 3 and not toks[2].startswith("#"):
            rn = parse_reg(toks[1])
            rm = parse_reg(toks[2])
            return enc_tst_cmp_cmn(op, rn, rm)

        # General dp: op rdn rm
        if len(toks) != 3:
            raise ValueError(f"Syntaxe DataProc: {op} rdn rm")
        rdn = parse_reg(toks[1])
        rm = parse_reg(toks[2])
        return enc_dp(op, rdn, rm)

    # LDR/STR SP:
    # ldr rt [ sp #offset ]   (on accepte: ldr rt [ sp #offset ] ou ldr rt [sp #offset])
    if op in ("ldr", "str"):
        # Expect tokens like: ldr r1 [ sp #8 ]
        # Minimal: ldr rt [ sp ] ; offset optional
        rt = parse_reg(toks[1])
        # find 'sp' and optional immediate
        if "sp" not in toks:
            raise ValueError(f"{op}: uniquement [sp, #offset] supporté")
        # offset in bytes in asm, but encoded imm8 = offset/4 in PARM :contentReference[oaicite:11]{index=11}
        imm_bytes = 0
        for t in toks:
            if t.startswith("#"):
                imm_bytes = parse_imm(t)
        if imm_bytes % 4 != 0:
            raise ValueError(f"{op}: offset doit être multiple de 4 (reçu {imm_bytes})")
        imm8 = imm_bytes // 4
        return enc_ldr_str_sp(op, rt, imm8)

    # ADD/SUB SP:
    # add sp #offset  (offset bytes, encoded /4) :contentReference[oaicite:12]{index=12}
    if op in ("add", "sub") and len(toks) >= 3 and toks[1] == "sp":
        imm_bytes = parse_imm(toks[2])
        if imm_bytes % 4 != 0:
            raise ValueError(f"{op} sp: offset doit être multiple de 4 (reçu {imm_bytes})")
        imm7 = imm_bytes // 4
        return enc_addsub_sp(op, imm7)

    raise ValueError(f"Instruction non supportée: {' '.join(toks)}")

def assemble(path_in: str) -> List[int]:
    lines = read_lines(path_in)
    labels, inst_lines = pass1_labels(lines)
    words: List[int] = []
    for pc, sl in enumerate(inst_lines):
        try:
            w = assemble_line(sl.tokens, pc, labels)
            words.append(w & 0xFFFF)
        except Exception as e:
            raise RuntimeError(f"Ligne {sl.lineno}: {sl.original}\n  -> {e}") from e
    return words

def write_logisim(words: List[int], path_out: str, per_line: int = 8) -> None:
    with open(path_out, "w", encoding="utf-8") as f:
        f.write("v2.0 raw\n")
        for i in range(0, len(words), per_line):
            chunk = words[i:i+per_line]
            f.write(" ".join(f"{w:04x}" for w in chunk) + "\n")

def main(argv: List[str]) -> int:
    if len(argv) < 3:
        print("Usage: asm_parm.py input.s output.bin", file=sys.stderr)
        return 2
    inp, outp = argv[1], argv[2]
    words = assemble(inp)
    write_logisim(words, outp)
    print(f"OK: {len(words)} instructions -> {outp}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
