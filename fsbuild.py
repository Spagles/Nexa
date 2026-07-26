import sys
from pathlib import Path

IGNORE_LIST = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".vscode",
    "node_modules",
    ".DS_Store",
    "venv",
    ".venv",
    "instances",
    "staging",
    "logs",
}


def generate_tree(dir_path: Path, prefix: str = ""):
    """Recursively yields a formatted visual filesystem tree."""
    try:
        # Fetch entries and filter out ignored files/folders
        entries = sorted(
            [e for e in dir_path.iterdir() if e.name not in IGNORE_LIST],
            key=lambda e: (e.is_file(), e.name.lower()),
        )
    except PermissionError:
        return

    # Iterate with indexing to detect the final item in the folder
    for index, entry in enumerate(entries):
        is_last = index == len(entries) - 1

        connector = "└── " if is_last else "├── "

        print(f"{prefix}{connector}{entry.name}")

        if entry.is_dir():
            next_prefix = prefix + ("    " if is_last else "│   ")
            generate_tree(entry, next_prefix)


if __name__ == "__main__":
    target_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")

    if target_path.exists() and target_path.is_dir():
        print(f"📁 {target_path.resolve().name}")
        generate_tree(target_path)
    else:
        print(f"Error: The path '{target_path}' is not a valid directory.")
