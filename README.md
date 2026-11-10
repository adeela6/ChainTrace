# ChainTrace

Blockchain-backed chain-of-custody tracking for digital evidence, built with FastAPI and SQLite.

## Setup

```bash
# 1. Clone
git clone https://github.com/adeela6/ChainTrace.git
cd ChainTrace

# 2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create your local config
copy .env.example .env         # Windows
# cp .env.example .env         # macOS / Linux

# 5. Generate a master key and paste it into CHAINTRACE_MASTER_KEY in .env
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# 6. Run
uvicorn app.main:app --reload
```

Never commit `.env`, databases, or anything under `storage/`.

## Tests

```bash
pytest                                  # all tests
python scripts/make_test_results.py     # run tests and regenerate docs/test-results.md
coverage run -m pytest && coverage report
```

Tests use a temporary database, storage folder and master key, so they never touch your real `.env` or data. See [docs/test-plan.md](docs/test-plan.md) for what is tested and why.

## Git workflow

- **No direct pushes to `main`.**
- One branch per task, prefixed by owner: `a/...`, `b/...`, `c/...`, `d/...` (e.g. `a/login-endpoint`).
- Open a pull request into `main`; it needs **one approving review** before merge.
