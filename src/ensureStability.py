# This function is called early during main.py to ensure everything required to run correctly
# is set up, and to fail early if not. This includes:
# - Checking for the presence of the BOT_TOKEN environment variable
# - Starting the PlayIt client if configured to use it
# - Loading instances from the registry and registering them with the InstanceManager

# Under the MIT License.

import os
import shutil
import subprocess
import sys
from pathlib import Path
import yaml
from services.nexaConfig import NexaConfig

def checkIfAbleToRun(config: NexaConfig):
    # Check if BOT_TOKEN is set
    token = os.getenv("BOT_TOKEN")
    protectedKey = os.getenv("NEXABOT_PROTECTED_KEY")
    if not token:
        print("You have not set up a bot token in your environment variables. Please set this up with the registry name 'BOT_TOKEN'.")
        input("Press Enter to continue . . .")
        sys.exit(1)

    if not protectedKey:
        print("You have not set up a protection key in your environment variables. Please set this up with the registry name 'NEXABOT_PROTECTED_KEY'.")
        input("Press Enter to continue . . .")
        sys.exit(1)

    # Check if PlayIt is configured and available
    use_playit = config.get("networking.usePlayIt", False)
    if use_playit:
        playit_path = shutil.which("playit")
        if not playit_path:
            print("PlayIt is configured but not found in PATH. Please install PlayIt and ensure it is accessible.")
            input("Press Enter to continue . . .")
            sys.exit(1)

    # Check for Java
    java_path = shutil.which("java")
    if not java_path:
        print("Java is required to run Minecraft servers but was not found in PATH. Please install Java and ensure it is accessible.")
        input("Press Enter to continue . . .")
        sys.exit(1)

    # Additional version check on Java, if it exists.

    if java_path:
        try:
            result = subprocess.run([java_path, "-version"], capture_output=True, text=True)
            version_info = result.stderr  # Java version info is typically in stderr
            if "version" in version_info:
                version_line = version_info.splitlines()[0]
                version_str = version_line.split('"')[1]  # Extract the version number
                major_version = int(version_str.split(".")[0])  # Get the major version
                if major_version < 25:
                    print(f"Java version {version_str} detected. Minecraft servers currently require Java 25 or higher. Please update your Java installation.")
                    input("Press Enter to continue . . .")
                    sys.exit(1)
        except Exception as e:
            print(f"An error occurred while checking Java version: {e}")
            input("Press Enter to continue . . .")
            sys.exit(1)

    # Check that a primary instance is configured and that it exists in the instance registry.
    primaryInstanceName = config.get("general.primaryInstance")
    if not primaryInstanceName:
        print("No primary instance is configured. Please set 'general.primaryInstance' in NexaBotConfig.yaml.")
        input("Press Enter to continue . . .")
        sys.exit(1)

    registryPath = Path("NexaInstanceRegistry.yaml")
    if not registryPath.exists():
        print(f"Instance registry not found at {registryPath}. Cannot verify primary instance.")
        input("Press Enter to continue . . .")
        sys.exit(1)

    with open(registryPath, "r", encoding="utf-8") as f:
        registryData = yaml.safe_load(f) or {}

    instances = registryData.get("instances") or {}
    if primaryInstanceName not in instances:
        print(f"Configured primary instance '{primaryInstanceName}' was not found in {registryPath}. Please check 'general.primaryInstance' in NexaBotConfig.yaml.")
        input("Press Enter to continue . . .")
        sys.exit(1)