@echo off
REM ============================================================================
REM  run_redteam_llm.bat - red-team the REAL model (Groq gpt-oss-120b).
REM  Quick profile: 72 runs (6 attacks x 3 vectors x 2 configs x 2 scenarios).
REM  Expect 1-3 hours and noticeable token use. It is resumable: if Groq rate
REM  limits you or you close the window, just double-click it again later.
REM ============================================================================
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
call venv\Scripts\activate.bat
if not exist run_logs mkdir run_logs

echo Red team (LLM) started %date% %time% > run_logs\20_redteam_llm_status.txt
python redteam\run_attacks.py --mode llm --delay 10 > run_logs\20_redteam_llm.txt 2>&1
if errorlevel 1 (echo FAILED >> run_logs\20_redteam_llm_status.txt) else (echo ok >> run_logs\20_redteam_llm_status.txt)
echo DONE %date% %time% >> run_logs\20_redteam_llm_status.txt

echo.
echo Finished. Summary: redteam\results\llm_summary.md
pause
