from .main import find_gadget, command
from shutil import which

if which("one_gadget") is None:
    raise Exception("Unable to locate one_gadget in path")