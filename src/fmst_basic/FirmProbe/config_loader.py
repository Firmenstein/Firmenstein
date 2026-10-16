import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from loguru import logger

class ConfigLoader:
    """
    Configuration loader for Firmenstein project.
    Loads and provides access to various service patterns and configurations.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration loader.
        
        Args:
            config_path: Path to the configuration file. If None, uses default path.
        """
        if config_path is None:
            # Default config path relative to this file's location
            self.config_path = Path(__file__).parent.parent / "config" / "services.yaml"
        else:
            self.config_path = Path(config_path)
        
        self._config: Dict[str, Any] = {}
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from YAML file."""
        try:
            if not self.config_path.exists():
                raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
            
            with open(self.config_path, 'r', encoding='utf-8') as file:
                self._config = yaml.safe_load(file) or {}
            
            logger.info(f"Configuration loaded from {self.config_path}")
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            self._config = {}
    
    def reload(self) -> None:
        """Reload configuration from file."""
        self._load_config()
    
    # Web-related getters
    @property
    def web_roots(self) -> List[str]:
        """Get list of potential web root directory names."""
        return self._config.get("web", {}).get("roots", [])
    
    @property
    def web_extensions(self) -> List[str]:
        """Get list of web file extensions."""
        return self._config.get("web", {}).get("extensions", [])
    
    # Backup-related getters
    @property
    def backup_tags(self) -> List[str]:
        """Get list of backup file tags."""
        return self._config.get("backup", {}).get("tags", [])
    
    # Service-related getters
    @property
    def http_servers(self) -> List[str]:
        """Get list of potential HTTP server binaries."""
        return self._config.get("services", {}).get("http_servers", [])
    
    @property
    def upnp_servers(self) -> List[str]:
        """Get list of potential UPnP server binaries."""
        return self._config.get("services", {}).get("upnp_servers", [])
    
    @property
    def dns_servers(self) -> List[str]:
        """Get list of potential DNS server binaries."""
        return self._config.get("services", {}).get("dns_servers", [])
    
    @property
    def dhcp_servers(self) -> List[str]:
        """Get list of potential DHCP server binaries."""
        return self._config.get("services", {}).get("dhcp_servers", [])
    
    def get_all_servers(self) -> List[str]:
        """Get all server binaries combined."""
        all_servers = []
        all_servers.extend(self.http_servers)
        all_servers.extend(self.upnp_servers)
        all_servers.extend(self.dns_servers)
        all_servers.extend(self.dhcp_servers)
        return list(set(all_servers))  # Remove duplicates
    
    def get_config_section(self, section: str) -> Dict[str, Any]:
        """
        Get a specific configuration section.
        
        Args:
            section: The configuration section name
            
        Returns:
            Dictionary containing the section configuration
        """
        return self._config.get(section, {})
    
    def get_config_value(self, *keys: str) -> Any:
        """
        Get a nested configuration value using dot notation.
        
        Args:
            *keys: Keys to traverse in order (e.g., "services", "http_servers")
            
        Returns:
            The configuration value or None if not found
        """
        value = self._config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value


# Global configuration instance
_config_instance: Optional[ConfigLoader] = None

def get_config(config_path: Optional[str] = None) -> ConfigLoader:
    """
    Get the global configuration instance.
    
    Args:
        config_path: Path to configuration file (only used on first call)
        
    Returns:
        ConfigLoader instance
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigLoader(config_path)
    return _config_instance


# For backward compatibility, provide constants that match your original naming
def load_constants():
    """Load constants in the original format for backward compatibility."""
    config = get_config()
    
    return {
        'WEBROOTS': config.web_roots,
        'WEB_EXTS': config.web_extensions,
        'BACKUP_TAGS': config.backup_tags,
        'POTENTIAL_HTTPSERV': config.http_servers,
        'POTENTIAL_UPNPSERV': config.upnp_servers,
        'POTENTIAL_DNSSERV': config.dns_servers,
        'POTENTIAL_DHCPSERV': config.dhcp_servers,
    }


if __name__ == "__main__":
    # Example usage    
    config = get_config()
    
    print("Web roots:", config.web_roots)
    print("HTTP servers:", config.http_servers)
    print("All servers:", len(config.get_all_servers()))
    
    # Backward compatibility test
    constants = load_constants()
    print("WEBROOTS:", constants['WEBROOTS']) 