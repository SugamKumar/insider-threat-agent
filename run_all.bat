@echo off
REM ============================================================================
REM  run_all.bat - sets up and runs the whole project, logging every step.
REM  Double-click it from File Explorer. Takes ~15-25 min (vector store rebuild
REM  + one full LLM pipeline run). Output for each step goes to run_logs\.
REM  The LLM red team is separate (run_redteam_llm.bat) because it takes hours.
REM ============================================================================
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

if not exist venv\Scripts\activate.bat (
    echo venv not found - creating it...
    python -m venv venv
)
call venv\Scripts\activate.bat

if not exist run_logs mkdir run_logs
echo Run started %date% %time% > run_logs\00_status.txt

call :step 01_pip_install "pip install -r requirements.txt"
call :step 02_check_groq "python check_groq.py"
call :step 03_rag_rebuild "python src\rag.py --yes"
call :step 04_pytest "python -m pytest -q"
call :step 05_detector_bench "python redteam\benchmark_detectors.py"
call :step 06_redteam_worstcase "python redteam\run_attacks.py --mode worst-case --all --fresh"
call :step 07_generate_hard "python src\log_generator.py --difficulty hard --suspicious 5 --normal 5 --seed 42"
call :step 08_pipeline_llm "python src\agent.py"
call :step 09_evaluate "python src\evaluate.py"
call :step 10_benchmark "python src\benchmark.py --with-llm"

echo ALL DONE %date% %time% >> run_logs\00_status.txt
echo.
echo ===================================================================
echo  Finished. Results are in run_logs\.
echo ===================================================================
type run_logs\00_status.txt
pause
exit /b

:step
set "NAME=%~1"
set "CMD=%~2"
echo.
echo ---- [%NAME%] %CMD%
%CMD% > run_logs\%NAME%.txt 2>&1
if errorlevel 1 (
    echo %NAME%: FAILED >> run_logs\00_status.txt
    echo      FAILED - see run_logs\%NAME%.txt
) else (
    echo %NAME%: ok >> run_logs\00_status.txt
    echo      ok
)
exit /b
