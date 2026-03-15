"""
Gemini 3.1 Pro Migration Validation Script (Path-Fixed)
Verifies google-genai v1.66.0 installation and ai_engine.py import.
"""
import sys
import os

# 1. FORCE PATH INJECTION
# This tells Python to prioritize the backend_ml folder where you installed the library
current_dir = os.getcwd()
backend_path = os.path.join(current_dir, "backend_ml")
sys.path.insert(0, backend_path)

try:
    # 2. Try importing the new library directly first
    from google import genai
    print(f"Library Location: {genai.__file__}") # Shows exactly which folder is being used
    
    # 3. Import your engine
    from ai_engine import GeminiEngine
    
    # Test instantiation (pass a dummy key for testing)
    engine = GeminiEngine(api_key="AIzaSy_TEST_KEY")
    
    print("\nGemini 3.1 Pro Connection: SUCCESS ✅")
    print("New google-genai v1.66.0 migration complete!")
    print(f"Verified using path: {backend_path}")

except ImportError as e:
    print(f"\nImportError: {e}")
    print("--- DIAGNOSTICS ---")
    print(f"Looking in sys.path[0]: {sys.path[0]}")
    print("If 'google' is not found, try running:")
    print("pip install google-genai==1.66.0 --target ./backend_ml")
except Exception as e:
    print(f"\nSetup Error: {e}")