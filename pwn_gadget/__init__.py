from pwn_gadget.logging import Logging as log
from .main import find_gadget
from shutil import which

if which("one_gadget") is None:
    log.warn("Could not find one_gadget in path")
    raise Exception("Unable to locate one_gadget in path")