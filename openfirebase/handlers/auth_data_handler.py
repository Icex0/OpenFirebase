"""Authentication Data Handler Module

This module handles saving and loading successful authentication data for 
the --resume --auth-only functionality.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional

from ..core.config import BLUE, GREEN, RESET, YELLOW


class AuthDataHandler:
    """Handles saving and loading authentication data for resume functionality."""

    @staticmethod
    def save_auth_data(
        project_id: str,
        api_key: str,
        package_name: Optional[str],
        cert_sha1: Optional[str],
        app_id: Optional[str],
        output_dir: str
    ) -> None:
        """Save successful authentication data to a JSON file.
        
        Args:
            project_id: The Firebase project ID that was successfully authenticated
            api_key: The API key that worked for authentication
            package_name: The package name used for X-Android-Package header
            cert_sha1: The SHA-1 certificate that worked for X-Android-Cert header
            app_id: The Google App ID for the project
            output_dir: Directory where to save the auth data file

        """
        auth_file_path = Path(output_dir) / "auth_data.json"

        # Load existing data if file exists
        existing_data = {}
        if auth_file_path.exists():
            try:
                with open(auth_file_path, encoding="utf-8") as f:
                    existing_data = json.load(f)
            except (json.JSONDecodeError, Exception):
                # If file is corrupted, start fresh
                existing_data = {}

        # Add or update the authentication data for this project
        existing_data[project_id] = {
            "api_key": api_key,
            "app_id": app_id,
            "package_name": package_name,
            "cert_sha1": cert_sha1,
            "validated": True
        }

        # Ensure output directory exists
        auth_file_path.parent.mkdir(parents=True, exist_ok=True)

        # Save updated data
        try:
            with open(auth_file_path, "w", encoding="utf-8") as f:
                json.dump(existing_data, f, indent=2, ensure_ascii=False)

            print(f"{GREEN}[AUTH]{RESET} Saved authentication data for project {project_id} to {auth_file_path.name}")
        except Exception as e:
            print(f"{YELLOW}[WARNING]{RESET} Failed to save authentication data: {e}")

    @staticmethod
    def load_auth_data(auth_file_path: str) -> Dict[str, Dict]:
        """Load authentication data from the auth data file.
        
        Args:
            auth_file_path: Path to the auth_data.json file
            
        Returns:
            Dictionary mapping project IDs to their authentication data

        """
        auth_path = Path(auth_file_path)

        if not auth_path.exists():
            print(f"{YELLOW}[AUTH]{RESET} Authentication data file not found: {auth_file_path}")
            return {}

        try:
            with open(auth_path, encoding="utf-8") as f:
                auth_data = json.load(f)

            print(f"{BLUE}[AUTH]{RESET} Loaded authentication data for {len(auth_data)} project(s) from {auth_path.name}")
            return auth_data
        except (json.JSONDecodeError, Exception) as e:
            print(f"{YELLOW}[WARNING]{RESET} Failed to load authentication data: {e}")
            return {}

    @staticmethod
    def get_validated_project_ids(auth_data: Dict[str, Dict]) -> List[str]:
        """Get list of project IDs that have valid authentication data.
        
        Args:
            auth_data: Authentication data dictionary
            
        Returns:
            List of project IDs with valid authentication

        """
        return [
            project_id for project_id, data in auth_data.items()
            if data.get("validated", False) and data.get("api_key")
        ]

    @staticmethod
    def get_auth_config_for_project(auth_data: Dict[str, Dict], project_id: str) -> Optional[Dict]:
        """Get authentication configuration for a specific project.
        
        Args:
            auth_data: Authentication data dictionary
            project_id: Project ID to get config for
            
        Returns:
            Dictionary with auth config or None if not found

        """
        if project_id not in auth_data:
            return None

        data = auth_data[project_id]
        if not data.get("validated", False) or not data.get("api_key"):
            return None

        return {
            "api_key": data["api_key"],
            "app_id": data.get("app_id"),
            "package_name": data.get("package_name"),
            "cert_sha1": data.get("cert_sha1")
        }
