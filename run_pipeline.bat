@echo off
REM Re-runs just the LLM pipeline, evaluation and benchmark (steps 08-10 of run_all.bat).
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
call venv\Scripts\activate.bat
if not exist run_logs mkdir run_logs
echo Pipeline run started %date% %time% > run_logs\30_status.txt
python src\agent.py > run_logs\08_pipeline_llm.txt 2>&1
if errorlevel 1 (echo 08_pipeline_llm: FAILED >> run_logs\30_status.txt) else (echo 08_pipeline_llm: ok >> run_logs\30_status.txt)
python src\evaluate.py > run_logs\09_evaluate.txt 2>&1
python src\benchmark.py --with-llm > run_logs\10_benchmark.txt 2>&1
echo DONE %date% %time% >> run_logs\30_status.txt
type run_logs\30_status.txt
type run_logs\09_evaluate.txt
echo.
echo Finished.
pause
