@echo off
title BruteShield - Log Analyzer API
color 0D
echo.
echo  =====================================================
echo   [*]  BruteShield -- Log Analyzer for Brute-Force
echo  =====================================================
echo.
echo  [1] Starting Flask API on http://localhost:5000 ...
echo  [2] Then open: frontend\index.html in your browser
echo.
echo  Keep this window open while using the app.
echo  Press Ctrl+C to stop the server.
echo.
cd /d "%~dp0backend"
python server.py
pause
