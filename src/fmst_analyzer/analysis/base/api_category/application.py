"""
Application Resource operations classification.

This module defines all application-level resource APIs that are managed by
specific application libraries or domain logic, not standard OS primitives.

Classification (2-category system):
- create: APIs that create new application resource instances (returns handle)
- info: APIs for global initialization/configuration (handle-free setup)
"""

from typing import List
from .base import BaseResourceOps


class ApplicationResourceOps(BaseResourceOps):
    """
    Application resource operations classifier.

    Handles APIs that operate on high-level, domain-specific resources
    managed by application libraries rather than the OS kernel.
    """

    @property
    def create_predefined(self) -> List[str]:
        return [
            # SQLite database handles
            "sqlite3_open",
            "sqlite3_open_v2",
            "sqlite3_open16",

            # SSL/TLS contexts
            "SSL_CTX_new",
            "SSL_SESSION_new",

            # OpenSSL BIO
            "BIO_new",
            "BIO_new_mem_buf",
            "BIO_new_socket",
            "BIO_new_connect",
            "BIO_new_accept",
            "BIO_new_file",
            "BIO_new_fp",

            # OpenSSL EVP
            "EVP_MD_CTX_new",
            "EVP_CIPHER_CTX_new",
            "EVP_PKEY_new",

            # libcurl handles
            "curl_easy_init",
            "curl_multi_init",
            "curl_share_init",
            "curl_url",

            # XML parsing (libxml2)
            "xmlNewDoc",
            "xmlNewParserCtxt",
            "xmlCreatePushParserCtxt",
            "xmlReaderForFile",
            "xmlReaderForMemory",

            # zlib compression contexts
            "deflateInit",
            "deflateInit2",
            "inflateInit",
            "inflateInit2",

            # Regular expression contexts
            "regcomp",
            "pcre_compile",
            "pcre2_compile",
        ]

    @property
    def info_predefined(self) -> List[str]:
        return [
            # SQLite global configuration
            "sqlite3_config",
            "sqlite3_initialize",

            # OpenSSL global initialization
            "SSL_library_init",
            "SSL_load_error_strings",
            "OpenSSL_add_all_algorithms",
            "OPENSSL_init_ssl",
            "OPENSSL_init_crypto",

            # libcurl global initialization
            "curl_global_init",
            "curl_global_cleanup",

            # XML global initialization
            "xmlInitParser",
            "xmlCleanupParser",
        ]
