from pwn_gadget.util import check_memory_permissions
from typing import Optional, List, Dict, Callable
from dataclasses import dataclass
from enum import Enum

import operator

class Result(Enum):
    Unsat = 1,
    Unknown = 2,
    Sat = 4,

class Operator:
    """
    Convert string of operator to callable operator
    """
    _mapping: Dict[str, Callable] = {
        "==": operator.eq,
        ">" : operator.gt,
        ">=": operator.ge,
        "<" : operator.lt,
        "<=": operator.le,
        "wr": check_memory_permissions,
        "argv": lambda: Result.Unknown,
        "envp": lambda: Result.Unknown,
    }
    def __init__(self, opstr: str):
        self.opstr: str = opstr

    def eval(self, arg1: int, arg2: int, gdb_api) -> Result:
        opfunc: Optional[Callable[[int, int], Result]] = self._mapping.get(self.opstr)
        if opfunc is None:
            raise Exception(f"No function for operator {self.opstr}")
        if self.opstr in "wr":
            result = opfunc(arg1, arg2, gdb_api)
        else:
            result = opfunc(arg1, arg2)
        return Result.Sat if result else Result.Unsat

@dataclass
class Constraint:
    arg1: str
    arg2: Optional[int]
    operation: Operator
    raw: str

@dataclass
class ConstraintGroup:
    constraints: List[Constraint]
    raw: str

@dataclass
class Gadget:
    address: int
    constraint_groups: List[ConstraintGroup]

type_map: Dict[str, str] = {
    "(s8)" : "(signed char)",
    "(u8)" : "(unsigned char)",
    "(s16)": "(signed short)",
    "(u16)": "(unsigned short)",
    "(s32)": "(signed int)",
    "(u32)": "(unsigned int)",
    "(s64)": "(signed long)",
    "(u64)": "(unsigned long)"
}
