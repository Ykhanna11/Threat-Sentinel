from enum import StrEnum


def enum_values[E: StrEnum](enum_type: type[E]) -> list[str]:
    return [member.value for member in enum_type]
