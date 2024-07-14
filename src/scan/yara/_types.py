from abc import ABC, abstractmethod
from typing import List, Optional, Dict


class StringMatchInstance(ABC):
    matched_data: bytes
    """Bytes of the matched data."""
    matched_length: int
    """Length of the matched data."""
    offset: int
    """Offset of the matched data."""
    xor_key: Optional[int]
    """XOR key found for the string."""

    @abstractmethod
    def plaintext(self) -> str:
        """Returns the plaintext version of the string after xor key is applied.
        If the string is not an xor string then no modification is done.
        """
        pass


class StringMatch(ABC):
    identifier: str
    """Name of the matching string"""
    instances: List[StringMatchInstance]
    """List of StringMatchInstance objects."""

    @abstractmethod
    def is_xor(self) -> bool:
        """Returns a boolean if the string is using the xor modifier."""
        pass


class Match(ABC):
    rule: str
    """Name of the matching rule."""
    namespace: str
    """Namespace associated to the matching rule."""
    tags: List[str]
    """Array of strings containing the tags associated to the matching rule."""
    meta: Dict[str, str]
    """Dictionary containing metadata associated to the matching rule."""
    strings: List[StringMatch]
    """List of StringMatch objects."""
