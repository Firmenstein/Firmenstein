import idapro  # Initialize native bindings at the backend boundary.
import ida_nalt
from ida_domain import Database
from ida_domain.database import IdaCommandOptions, DatabaseError
from loguru import logger
from pathlib import Path

class IDBManager:
    _current_idb_path: str = None
    _current_idb: Database = None
    # Per-binary graph caches may have been produced from a different
    # checkout.  During one pickle load, callers provide the current source
    # ELF and IDB directory so nested IDAFunction objects can rebind their
    # runtime paths before validating them.  This is deliberately transient;
    # it is never persisted in a cache.
    _cache_rebase_binary_path: Path | None = None
    _cache_rebase_idb_dir: Path | None = None

    @classmethod
    def begin_cache_rebase(cls, binary_path: Path, idb_dir: Path) -> None:
        cls._cache_rebase_binary_path = Path(binary_path).absolute().resolve()
        cls._cache_rebase_idb_dir = Path(idb_dir).absolute().resolve()

    @classmethod
    def end_cache_rebase(cls) -> None:
        cls._cache_rebase_binary_path = None
        cls._cache_rebase_idb_dir = None

    def create_idb(binary_path: Path, idb_path: Path, ida_options: IdaCommandOptions):
        """Create a new IDB for the given binary path using the global management system."""
        IDBManager.close_current_idb()
        try:
            IDBManager._current_idb = Database.open(str(binary_path), ida_options)
            IDBManager._current_idb_path = str(idb_path)
            IDBManager._require_input_identity()
            logger.debug(f"Created new IDA database: {idb_path}, idb open status: {IDBManager._current_idb.is_open()}")
        except DatabaseError as e:
            IDBManager._current_idb = None
            IDBManager._current_idb_path = None
            raise RuntimeError(f"Failed to create binary/IDB {binary_path} in IDA: {e}")
        finally:
            IDBManager.close_current_idb()

    def open_idb(ida_path: Path, ida_options: IdaCommandOptions):
        """Open this instance's IDB using the global management system."""
        IDBManager._switch_idb_if_needed(ida_path, ida_options)
        return True
    
    def close_idb(ida_path: Path):
        """Close the current IDB if it matches this instance's path."""
        if IDBManager._current_idb_path == str(ida_path):
            IDBManager.close_current_idb()
        else:
            raise RuntimeError("Attempted to close an IDB that is not currently opened.")

    @staticmethod
    def get_current_idb():
        """Get the currently opened IDB instance."""
        return IDBManager._current_idb
    
    @staticmethod
    def get_current_idb_path():
        """Get the path of the currently opened IDB."""
        return IDBManager._current_idb_path

    @staticmethod
    def close_current_idb():
        """Close the current IDB and reset global state."""
        current_idb = IDBManager._current_idb
        current_path = IDBManager._current_idb_path
        try:
            if current_idb and current_idb.is_open():
                try:
                    IDBManager._require_input_identity()
                except RuntimeError:
                    # IDALib can return an open database whose input metadata
                    # has disappeared. Saving that state destroys the valid
                    # on-disk IDB; discard it and retain an explicit failure.
                    current_idb.close(save=False)
                    raise
                current_idb.close(save=True)
                logger.debug(f"Closed current IDA database: {current_path}")
        finally:
            # A failed native close must not leave Python-side state pointing
            # at a database that can no longer be used safely.
            IDBManager._current_idb = None
            IDBManager._current_idb_path = None

    @staticmethod
    def _require_input_identity():
        if not ida_nalt.retrieve_input_file_sha256():
            raise RuntimeError(
                f"IDA database lost its input SHA256: {IDBManager._current_idb_path}; "
                "refusing to save incomplete native state"
            )

    @staticmethod
    def _switch_idb_if_needed(target_path: Path, ida_options: IdaCommandOptions):
        """Switch to the target IDB if it's different from the current one."""
        target_path_str = str(target_path)
        current_idb = IDBManager._current_idb
        if (
            IDBManager._current_idb_path == target_path_str
            and current_idb is not None
            and current_idb.is_open()
        ):
            return

        IDBManager.close_current_idb()
        try:
            IDBManager._current_idb = Database.open(target_path_str, ida_options)
            IDBManager._current_idb_path = target_path_str
            IDBManager._require_input_identity()
            logger.debug(f"Opened new IDA database: {target_path_str}, idb open status: {IDBManager._current_idb.is_open()}")
        except Exception as e:
            current_idb = IDBManager._current_idb
            try:
                if current_idb and current_idb.is_open():
                    current_idb.close(save=False)
            finally:
                IDBManager._current_idb = None
                IDBManager._current_idb_path = None
            raise RuntimeError(f"Failed to open binary/IDB {target_path} in IDA: {e}")
