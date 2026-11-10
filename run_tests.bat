@echo off
REM Installs pytest into the venv (if missing) and runs the offline test suite.
cd /d "%~dp0"
set PYTHONUTF8=1
call venv\Scripts\activate.bat
if not exist run_logs mkdir run_logs
python -m pip install pytest > run_logs\11_pytest_install.txt 2>&1
python -m pytest -q > run_logs\12_pytest.txt 2>&1
if errorlevel 1 (echo TESTS FAILED - see run_logs\12_pytest.txt) else (echo All tests passed.)
type run_logs\12_pytest.txt | more
pause
