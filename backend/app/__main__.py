"""Run the local prototype bound to loopback only."""

import uvicorn

from backend.app.core.config import HOST, PORT


if __name__ == "__main__":
    uvicorn.run("backend.app.main:app", host=HOST, port=PORT, reload=False)
