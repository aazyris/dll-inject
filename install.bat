@echo off
title DLL Injector - Installation
color 0b

echo [*] Installation des dependances...
pip install pycryptodome pywin32 psutil requests pystyle pefile

echo [*] Installation terminee!
echo [*] Demarrage du programme...
timeout /t 2 >nul

start "" python dllinject.py
exit 