"""OCSF normalization: raw vendor records in, one schema out."""

from .base import Mapper, MapperRegistry, NormalizationError, register, registry
from . import mappers  # noqa: F401  (import registers the built-in mappers)

__all__ = [
    "Mapper",
    "MapperRegistry",
    "NormalizationError",
    "register",
    "registry",
    "normalize",
    "normalize_many",
]

normalize = registry.normalize
normalize_many = registry.normalize_many
