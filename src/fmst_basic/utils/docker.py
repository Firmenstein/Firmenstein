import docker
from loguru import logger
from typing import Tuple, List

def docker_run(image: str, command: list, 
               mounting: List[Tuple[str, str]]) -> Tuple[int, str, str]:
    """
    Run a command in a Docker container with volume mounting.
    
    Args:
        image: Docker image name to use
        command: Command list to execute in the container
        
    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    try:
        # 1. Check if docker is running
        client = docker.from_env()
        client.ping()  # This will raise an exception if Docker is not running
        
        # 2. Run the command in container with volume mount
        container = client.containers.run(
            image=image,
            command=command,
            volumes={host_path: {'bind': container_path, 'mode': 'rw'} for host_path, container_path in mounting},
            detach=True,
            tty=True,
            remove=False  # We'll remove manually to get the exit code
        )
        
        # Wait for container to finish and get result
        result = container.wait()
        exit_code = result['StatusCode']
        
        # Get separate stdout and stderr
        try:
            stdout_logs = container.logs(stdout=True, stderr=False, stream=False)
            stderr_logs = container.logs(stdout=False, stderr=True, stream=False)
            stdout = stdout_logs.decode('utf-8') if stdout_logs else ""
            stderr = stderr_logs.decode('utf-8') if stderr_logs else ""
        except:
            # Fallback to combined logs if separate retrieval fails
            logger.exception("Failed to retrieve separate stdout/stderr logs.")
            
        # Remove the container
        container.remove()
        
        # docker will merge the stderr into stdout
        stderr += stdout
        return (exit_code, stdout, stderr)
    
    except Exception as e:
        raise RuntimeError(f"Failed to run command in Docker: {str(e)}")

