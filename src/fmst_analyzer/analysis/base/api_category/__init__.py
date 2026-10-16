try:
    from .base import BaseResourceOps, APICategory
    from .base import get_all_predefined_resource_apis
except ImportError:
    raise ImportError("Failed to import.")
