from .main import find_gadget
from shutil import which

if which("one_gadget") is None:
    print("[!] Could not find one_gadget in path")
    raise Exception("Unable to locate one_gadget in path")