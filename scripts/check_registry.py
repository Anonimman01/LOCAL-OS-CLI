import os
import sys
os.chdir(r'c:\Users\user\Desktop\browser')
sys.path.insert(0, os.getcwd())
from modules import registry
from core.config import Config
Config.load()
print('registry size', len(registry))
for key in registry.keys():
    desc = registry.get(key)
    ok, miss = desc.check_deps()
    print(f"{key}: deps_ok={ok}, missing={miss}")
    try:
        inst = desc.get_instance()
        print(f"  loaded: {type(inst).__name__}")
    except Exception as e:
        print(f"  ERROR: {type(e).__name__}: {e}")
