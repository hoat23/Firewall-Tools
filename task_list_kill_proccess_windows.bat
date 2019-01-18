@echo off
echo List processs
tasklist /fi "imagename eq python.exe"

echo Kill process

taskkill /fi "imagename eq python.exe" /f

echo kill by id

taskill /pid 1234 /f