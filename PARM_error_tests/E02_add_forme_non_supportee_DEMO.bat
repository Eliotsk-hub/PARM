@echo off
setlocal
cd /d "%~dp0.."

set "SRC=PARM_error_tests\E02_add_forme_non_supportee.s"
set "OUT=PARM_error_tests\E02_add_forme_non_supportee.hex"

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
