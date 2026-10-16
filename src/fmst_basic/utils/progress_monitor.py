"""
Progress monitoring with rich for API dependency graph analysis.
"""
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.live import Live
from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from typing import Optional, List
import threading
import time
from contextlib import contextmanager

class Monitor:
    """
    Progress monitor for API dependency graph analysis using rich.
    
    Provides a clean interface with:
    - Overall progress bar for root API functions
    - Current processing status
    - Real-time log output below the progress area
    """
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.layout = Layout()
        
        # Progress tracking
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=False
        )
        
        # Task IDs
        self.main_task_id: Optional[int] = None
        self.current_status = "Initializing..."
        self.logs: List[str] = []
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Live display
        self.live: Optional[Live] = None
    
    def start_monitoring(self, total_roots: int):
        """Start the progress monitoring."""
        with self._lock:
            self.main_task_id = self.progress.add_task(
                "Processing root API functions", 
                total=total_roots
            )
        
        # Setup layout
        self._setup_layout()
        
        # Start live display
        self.live = Live(
            self.layout, 
            console=self.console, 
            refresh_per_second=10,
            transient=False
        )
        self.live.start()
    
    def stop_monitoring(self):
        """Stop the progress monitoring."""
        if self.live:
            self.live.stop()
            self.live = None
    
    def update_progress(self, advance: int = 1):
        """Update the main progress bar."""
        with self._lock:
            if self.main_task_id is not None:
                self.progress.update(self.main_task_id, advance=advance)
    
    def update_status(self, status: str):
        """Update the current processing status."""
        with self._lock:
            self.current_status = status
            self._update_layout()
    
    def add_log(self, message: str, level: str = "INFO"):
        """Add a log message to the display."""
        with self._lock:
            timestamp = time.strftime("%H:%M:%S")
            formatted_msg = f"[{timestamp}] [{level}] {message}"
            self.logs.append(formatted_msg)
            
            # Keep only last 10 log entries to avoid clutter
            if len(self.logs) > 10:
                self.logs = self.logs[-10:]
            
            self._update_layout()
    
    def _setup_layout(self):
        """Setup the layout structure."""
        self.layout.split_column(
            Layout(name="progress", size=6),
            Layout(name="status", size=3),
            Layout(name="logs", ratio=1)
        )
        self._update_layout()
    
    def _update_layout(self):
        """Update the layout content."""
        if not hasattr(self, 'layout'):
            return
            
        # Progress section
        self.layout["progress"].update(Panel(self.progress, title="Analysis Progress"))
        
        # Status section
        status_text = Text(f"Current: {self.current_status}", style="bold green")
        self.layout["status"].update(Panel(status_text, title="Status"))
        
        # Logs section
        if self.logs:
            log_text = "\n".join(self.logs)
        else:
            log_text = "No logs yet..."
        
        self.layout["logs"].update(Panel(log_text, title="Recent Logs", border_style="dim"))
    
    @contextmanager
    def processing_root(self, root_name: str, root_address: str):
        """Context manager for processing a single root API function."""
        self.update_status(f"Processing {root_name} at {root_address}")
        self.add_log(f"Starting traversal from root API function: {root_name} at {root_address}")
        
        try:
            yield
        finally:
            self.update_progress(1)
            self.add_log(f"Completed processing {root_name}")
    
    def log_debug(self, message: str):
        """Add a debug log (won't be displayed in main logs to avoid clutter)."""
        # For debug messages, we can choose to not display them or display with lower priority
        pass
    
    def log_info(self, message: str):
        """Add an info log."""
        self.add_log(message, "INFO")
    
    def log_warning(self, message: str):
        """Add a warning log."""
        self.add_log(message, "WARN")
    
    def log_error(self, message: str):
        """Add an error log."""
        self.add_log(message, "ERROR")


# Singleton instance for global access
_monitor_instance: Optional[Monitor] = None


def get_monitor() -> Monitor:
    """Get the global monitor instance."""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = Monitor()
    return _monitor_instance


def set_monitor(monitor: Monitor):
    """Set the global monitor instance."""
    global _monitor_instance
    _monitor_instance = monitor