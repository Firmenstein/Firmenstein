"""
Thread resource operations classification.

This module defines pthread-related APIs.

Classification (2-category system):
- create: APIs that create new thread resources (thread, mutex, cond, rwlock, key, etc.)
- info: APIs querying thread identity or managing thread-local storage
"""
from typing import List
from .base import BaseResourceOps

class ThreadResourceOps(BaseResourceOps):
    """
    Thread resource operations classifier.

    Handles pthread APIs for thread lifecycle and synchronization primitive creation.
    """

    @property
    def create_predefined(self) -> List[str]:
        return [
            # Thread creation
            "pthread_create",

            # Synchronization primitive initialization
            "pthread_mutex_init",
            "pthread_cond_init",
            "pthread_rwlock_init",
            "pthread_barrier_init",
            "pthread_spin_init",

            # Thread-local storage key creation
            "pthread_key_create",

            # Attribute object initialization
            "pthread_attr_init",
            "pthread_mutexattr_init",
            "pthread_condattr_init",
            "pthread_rwlockattr_init",
            "pthread_barrierattr_init",
        ]

    @property
    def info_predefined(self) -> List[str]:
        return [
            # Thread identification (implicit self)
            "pthread_self",
            "pthread_equal",

            # Thread-local storage (key info about per-thread data)
            "pthread_getspecific",
            "pthread_setspecific",

            # Thread attribute configuration (key setup info)
            "pthread_attr_setdetachstate",
            "pthread_attr_setstacksize",
        ]
