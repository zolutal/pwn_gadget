import os
try:
    import gdb
except ImportError:
    raise Exception("pwn_gadget cannot be run standalone, must be attached to a gdb instance")

import pwn_gadget

class PwnGadgetCommand(gdb.Command):
    def __init__(self):
        super(PwnGadgetCommand, self).__init__("pwn_gadget", gdb.COMMAND_USER)

    def invoke(self, args_str: str, from_tty):
        pwn_gadget.command(gdb, args_str)
PwnGadgetCommand()


