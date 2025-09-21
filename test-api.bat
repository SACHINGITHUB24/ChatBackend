@echo off
echo Testing MongoDB Connection and API Endpoints
echo =============================================
echo.

echo 1. Testing MongoDB connection...
node test-connection.js
echo.

echo 2. Starting server in background...
start /B npm start
timeout /t 3 /nobreak > nul
echo.

echo 3. Testing API endpoints with curl...
echo.

echo Testing server health:
curl -X GET http://localhost:3000/api/health
echo.
echo.

echo Testing login endpoint (should fail - no user exists yet):
curl -X POST http://localhost:3000/api/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"admin\",\"password\":\"admin123\"}"
echo.
echo.

echo 4. Creating admin user...
node init-admin.js
echo.

echo 5. Testing login with admin credentials:
curl -X POST http://localhost:3000/api/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"admin\",\"password\":\"admin123\"}"
echo.
echo.

echo Testing complete!
pause
