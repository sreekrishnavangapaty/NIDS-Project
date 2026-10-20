"""Root Streamlit app launcher."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from dashboard.app import main

if __name__ == "__main__":
    main()
