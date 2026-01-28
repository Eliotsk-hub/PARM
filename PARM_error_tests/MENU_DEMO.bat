@echo off
setlocal
cd /d "%~dp0"

echo =================== PARM — MENU DEMO ===================
echo Choisis un test a lancer (ouvre une nouvelle fenetre):
echo.
echo  1) OK_minimal
echo  2) E02_add_forme_non_supportee (recommandé)
echo  3) E08_label_inconnu (recommandé)
echo  4) E06_immediat_trop_grand (recommandé)
echo  5) Lancer TOUT (1 par 1)
echo.
set /p choice="Entrez un numero: "

if "%choice%"=="1" start "" "%~dp0OK_minimal_DEMO.bat"
if "%choice%"=="2" start "" "%~dp0E02_add_forme_non_supportee_DEMO.bat"
if "%choice%"=="3" start "" "%~dp0E08_label_inconnu_DEMO.bat"
if "%choice%"=="4" start "" "%~dp0E06_immediat_trop_grand_DEMO.bat"
if "%choice%"=="5" goto :all
goto :end

:all
call "%~dp0OK_minimal_DEMO.bat"
call "%~dp0E02_add_forme_non_supportee_DEMO.bat"
call "%~dp0E08_label_inconnu_DEMO.bat"
call "%~dp0E06_immediat_trop_grand_DEMO.bat"
call "%~dp0E05_registre_hors_plage_DEMO.bat"
call "%~dp0E01_mnemonic_inconnu_DEMO.bat"
call "%~dp0E03_operande_manquant_DEMO.bat"
call "%~dp0E04_virgules_absentes_DEMO.bat"
call "%~dp0E07_format_immediat_invalide_DEMO.bat"
call "%~dp0E09_label_duplique_DEMO.bat"
call "%~dp0E10_ldr_base_non_supportee_DEMO.bat"
call "%~dp0E11_immediat_negatif_DEMO.bat"
goto :end

:end
endlocal
