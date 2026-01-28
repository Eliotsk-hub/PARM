@echo off
setlocal
cd /d "%~dp0.."

set "SRC=PARM_error_tests\E08_label_inconnu.s"
set "OUT=PARM_error_tests\E08_label_inconnu.hex"

echo.
echo ===================== DEMO ASSEMBLEUR =====================
echo Dossier : %CD%
echo Source  : %SRC%
echo Sortie  : %OUT%
echo ===========================================================
echo.

if not exist "asm_parm.py" (
  echo [ERREUR] asm_parm.py introuvable dans %CD%
  pause
  exit /b 1
)

python asm_parm.py "%SRC%" -o "%OUT%"

echo.
pause
endlocal
