"""
Verification Manager

Handles state verification and change validation for all tools.
"""

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


class VerificationManager:
    """
    Manages state verification and change validation.

    Features:
    - Compare before/after states
    - Validate data integrity
    - Check structural requirements
    - Custom verification rules
    """

    def __init__(self):
        """Initialize verification manager."""
        self.verification_rules = []

    def add_rule(self, rule_func: callable, name: str):
        """
        Add a custom verification rule.

        Args:
            rule_func: Function that takes (state) and returns (bool, str)
                      Returns (True, "") if valid, (False, "error message") if invalid
            name: Human-readable name for the rule
        """
        self.verification_rules.append({
            "name": name,
            "func": rule_func
        })
        logger.debug(f"Added verification rule: {name}")

    def verify_state(self, state: Dict[str, Any]) -> tuple[bool, List[str]]:
        """
        Verify state against all registered rules.

        Args:
            state: State dictionary to verify

        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []

        for rule in self.verification_rules:
            try:
                is_valid, error_msg = rule["func"](state)
                if not is_valid:
                    errors.append(f"{rule['name']}: {error_msg}")
            except Exception as e:
                errors.append(f"{rule['name']}: Exception during verification: {e}")

        is_valid = len(errors) == 0

        if is_valid:
            logger.debug("State verification passed")
        else:
            logger.warning(f"State verification failed: {len(errors)} error(s)")
            for error in errors:
                logger.warning(f"  - {error}")

        return is_valid, errors

    def compare_states(
        self,
        before: Dict[str, Any],
        after: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Compare two states and return differences.

        Args:
            before: State before operation
            after: State after operation

        Returns:
            Dictionary with comparison results:
            {
                'changed': True/False,
                'added': [...],
                'removed': [...],
                'modified': [...],
                'unchanged': [...]
            }
        """
        result = {
            'changed': False,
            'added': [],
            'removed': [],
            'modified': [],
            'unchanged': []
        }

        # For now, simple JSON comparison
        # Can be enhanced for deep diff analysis
        before_json = json.dumps(before, sort_keys=True)
        after_json = json.dumps(after, sort_keys=True)

        result['changed'] = (before_json != after_json)

        return result

    def calculate_hash(self, data: Dict[str, Any]) -> str:
        """
        Calculate hash of state for integrity checking.

        Args:
            data: Data to hash

        Returns:
            SHA256 hex digest
        """
        data_json = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_json.encode()).hexdigest()

    def verify_integrity(
        self,
        data: Dict[str, Any],
        expected_hash: str
    ) -> bool:
        """
        Verify data integrity against expected hash.

        Args:
            data: Data to verify
            expected_hash: Expected SHA256 hash

        Returns:
            True if hash matches
        """
        actual_hash = self.calculate_hash(data)
        matches = (actual_hash == expected_hash)

        if not matches:
            logger.warning(f"Integrity check failed!")
            logger.warning(f"  Expected: {expected_hash}")
            logger.warning(f"  Actual:   {actual_hash}")

        return matches

    def verify_structure(
        self,
        data: Dict[str, Any],
        required_keys: List[str],
        optional_keys: Optional[List[str]] = None
    ) -> tuple[bool, List[str]]:
        """
        Verify data structure has required keys.

        Args:
            data: Data to verify
            required_keys: Keys that must be present
            optional_keys: Keys that may be present (for validation)

        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []

        # Check required keys
        for key in required_keys:
            if key not in data:
                errors.append(f"Missing required key: {key}")

        # Check for unexpected keys (if optional_keys specified)
        if optional_keys is not None:
            allowed_keys = set(required_keys + optional_keys)
            for key in data.keys():
                if key not in allowed_keys:
                    errors.append(f"Unexpected key: {key}")

        is_valid = len(errors) == 0
        return is_valid, errors

    def verify_count(
        self,
        data: Dict[str, Any],
        key: str,
        min_count: Optional[int] = None,
        max_count: Optional[int] = None,
        exact_count: Optional[int] = None
    ) -> tuple[bool, str]:
        """
        Verify item count in data.

        Args:
            data: Data to verify
            key: Key to check count for
            min_count: Minimum count (inclusive)
            max_count: Maximum count (inclusive)
            exact_count: Exact count required

        Returns:
            Tuple of (is_valid, error message)
        """
        if key not in data:
            return False, f"Key '{key}' not found"

        value = data[key]

        # Determine count based on type
        if isinstance(value, (list, dict, str)):
            count = len(value)
        else:
            return False, f"Cannot determine count for type: {type(value)}"

        # Check count constraints
        if exact_count is not None:
            if count != exact_count:
                return False, f"Expected exactly {exact_count} items, got {count}"

        if min_count is not None:
            if count < min_count:
                return False, f"Expected at least {min_count} items, got {count}"

        if max_count is not None:
            if count > max_count:
                return False, f"Expected at most {max_count} items, got {count}"

        return True, ""
