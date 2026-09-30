from src.scanners.base import BaseScanner
from src.models.schemas import RawFinding
import logging

logger = logging.getLogger(__name__)

class SecretHeaderScanner(BaseScanner):
    name = "demo-plugin"

    def is_available(self) -> bool:
        return True

    def run(self, target: str) -> list[RawFinding]:
        logger.info(f"Demo Plugin: Scanning {target} for secret headers...")
        
        # Simulated finding to prove the plugin loaded and ran
        return [
            RawFinding(
                tool_source=self.name,
                file=target,
                line_start=0,
                severity="INFO",
                vuln_type="INFORMATION_DISCLOSURE",
                description="Demo plugin successfully loaded and executed against the target.",
                rule_id="demo-plugin-execution",
                cwe_id="CWE-200",
                confidence=1.0,
                code_snippet="Plugin System is Active",
                raw={"target": target}
            )
        ]
