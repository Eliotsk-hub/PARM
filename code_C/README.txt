# PARM - Compilation C -> ASM -> HEX Logisim

Ce projet permet d’exécuter du code C (simple) sur le processeur PARM en passant par :
1) Compilation du C en assembleur Thumb (`.s`) avec clang
2) Assemblage du `.s` en fichier Logisim (`.hex`, format `v2.0 raw`) avec `asm_parm.py`

## Prérequis

### Recommandé : Ubuntu via WSL (Windows)
- Installer WSL + Ubuntu
- Installer clang

Dans Ubuntu (WSL) :
```bash
sudo apt update
sudo apt apt install clang
clang -S -target arm-none-eabi -mcpu=cortex-m0 -O0 -mthumb -nostdlib -I./Code_c Code_c/main.c

Dans un terminal (PowerShell) :
python Code_c/asm_parm.py Code_c/main.s -o Code_c/out.hex
