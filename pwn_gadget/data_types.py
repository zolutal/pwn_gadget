from typing import Optional, List, NamedTuple, Dict, Callable, Tuple
from dataclasses import dataclass

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
        "<=": operator.le
    }
    def __init__(self, opstr: str):
        self.opstr: str = opstr

    def eval(self, arg1, arg2) -> bool:
        #TODO: implement
        if self.opstr in "wr":
            return False 
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