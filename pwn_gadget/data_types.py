from typing import Optional, List, Dict, Callable
from dataclasses import dataclass

from pwn_gadget.util import check_memory_permissions
import operator

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
        "wr": check_memory_permissions
    }
    def __init__(self, opstr: str):
        self.opstr: str = opstr

    def eval(self, arg1: int, arg2: int, gdb_api) -> bool:
        if self.opstr in "wr":
            return self._mapping.get(self.opstr)(arg1, arg2, gdb_api)
        return self._mapping.get(self.opstr)(arg1, arg2)

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
    "(s32)": "(signed int)",
    "(u32)": "(unsigned int)",
    "(s64)": "(signed long)",
    "(u64)": "(unsigned long)"
}