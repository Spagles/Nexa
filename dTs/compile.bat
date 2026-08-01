python -m nuitka ^
  --onefile ^
  --output-filename=nexa-v0.2.2.exe ^
  --output-dir=dist ^
  --company-name="StormCode" ^
  --product-name="Nexa" ^
  --file-version=0.2.2.0 ^
  --product-version=0.2.2.0 ^
  --file-description="Nexa" ^
  --copyright="Copyright (c) 2026 StormCode & Contributors" ^
  --assume-yes-for-downloads ^
  --follow-imports ^
  src/main.py