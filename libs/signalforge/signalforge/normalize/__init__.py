"""OCSF normalization: raw vendor records in, one schema out."""

from . import mappers  # noqa: F401  (import registers the built-in mappers)
from .base import Mapper, MapperRegistry, NormalizationError, register, registry

__all__ = [
    "Mapper",
    "MapperRegistry",
    "NormalizationError",
    "normalize",
    "normalize_many",
    "register",
    "registry",
]

normalize = registry.normalize
normalize_many = registry.normalize_many
