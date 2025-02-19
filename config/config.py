from pathlib import Path

# The directory where config.py is located (i.e. the config directory)
CONFIG_DIR = Path(__file__).resolve().parent

# The base project directory (one level up from config)
BASE_DIR = CONFIG_DIR.parent

# Default Logging
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "kali-pifi.log"



