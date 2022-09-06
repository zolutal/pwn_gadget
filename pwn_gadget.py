import os
try:
    import gdb
except ImportError:
    raise Exception("pwn_gadget cannot be run standalone, must be attached to a gdb instance")

# stop the weird errors that happen importing pwntools in gdb from happening
# TODO remove this when independence from pwntools is verfied
os.environ["PWNLIB_NOTERM"] = "1"
import pwn_gadget

class PwnGadgetCommand(gdb.Command):
    def __init__(self):
        super(PwnGadgetCommand, self).__init__("pwn_gadget", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        args = arg.split(" ")
        if len(args) != 1:
            print("Usage: pwn_gadget <path/to/libc>")
            return
        pwn_gadget.find_gadget(gdb, args[0])
PwnGadgetCommand()


