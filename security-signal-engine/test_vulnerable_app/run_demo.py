import subprocess
import sys
import time
import requests
import json
from pathlib import Path

def wait_for_server(url, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            requests.get(url)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(0.5)
    return False

def main():
    base_dir = Path(__file__).parent.parent
    server_script = Path(__file__).parent / "vulnerable_server.py"
    
    print("=" * 60)
    print("  Starting Vulnerable Test Application")
    print("=" * 60)
    
    # Start the server in the background
    server_process = subprocess.Popen(
        [sys.executable, str(server_script)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    
    if not wait_for_server("http://127.0.0.1:5001"):
        print("Failed to start server.")
        server_process.kill()
        return
        
    print("\nServer is running. Starting Security Signal Engine Scan...\n")
    
    # Prepare custom config for the scan to load the demo plugin
    config = {
        "plugins": {
            "enabled": True,
            "plugin_dir": str(Path(__file__).parent / "plugins")
        },
        "url_scanner": {
            "max_requests_per_scan": 500
        }
    }
    
    config_path = Path(__file__).parent / "test_config.yaml"
    
    # Write yaml config
    with open(config_path, "w") as f:
        f.write("plugins:\n")
        f.write("  enabled: true\n")
        f.write(f"  plugin_dir: {Path(__file__).parent / 'plugins'}\n")
        f.write("url_scanner:\n")
        f.write("  max_requests_per_scan: 500\n")
    
    try:
        # Run the scanner
        # Use python -m to run the CLI
        cmd = [
            sys.executable, "-m", "src.cli",
            "scan", "--url", "http://127.0.0.1:5001",
            "--no-llm"  # Disable LLM to make the demo faster and deterministic
        ]
        
        # Set env var for config
        env = os.environ.copy()
        env["SSE_PLUGINS__PLUGIN_DIR"] = str(Path(__file__).parent / "plugins")
        env["SSE_URL_SCANNER__MAX_REQUESTS_PER_SCAN"] = "500"
        
        print(f"Running command: {' '.join(cmd)}\n")
        
        # Run scanner and stream output
        scanner_process = subprocess.Popen(
            cmd,
            cwd=str(base_dir),
            env=env
        )
        scanner_process.wait()
        
    finally:
        print("\nStopping vulnerable server...")
        server_process.kill()
        if config_path.exists():
            config_path.unlink()
            
    print("\nDemo complete!")

if __name__ == "__main__":
    import os
    main()
