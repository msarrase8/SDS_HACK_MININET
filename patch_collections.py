import collections

# Reemplazar MutableMapping en collections con la versión correcta
if not hasattr(collections, 'MutableMapping'):
    from collections.abc import MutableMapping
    collections.MutableMapping = MutableMapping
