# QuantumShield frontend

Local React, TypeScript, and Vite interface for the FastAPI prototype.

## Run locally

1. Start the backend from the repository root with the project virtual environment:

   ```powershell
   .\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
   ```

2. Install the exact frontend versions recorded in `package-lock.json` and start Vite:

   ```powershell
   cd frontend
   npm ci
   npm run dev
   ```

3. Open the local Vite URL shown in the terminal. The backend allows the configured
   `localhost:5173` and `127.0.0.1:5173` origins.

`VITE_API_BASE_URL` may select either `http://127.0.0.1:8000` or
`http://localhost:8000`. The API client rejects non-loopback or non-HTTP URLs so
passphrases and file contents cannot be sent to a remote server by an accidental
configuration change.

The UI uses the backend's real health, key-management, trust-store, and
`.qshield` endpoints. It does not store passphrases in browser storage. This is
an academic local prototype and is not production-ready.
