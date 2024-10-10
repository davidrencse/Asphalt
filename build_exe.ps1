$ErrorActionPreference = "Stop"

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -r requirements-build.txt
