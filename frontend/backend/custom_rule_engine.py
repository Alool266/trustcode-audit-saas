"""
Custom Rule Engine for TrustCode AI
Allows users to define custom detection rules in YAML format.
"""

import re
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional, Pattern
from dataclasses import dataclass, field
from abc import ABC, abstractmethod


@dataclass
class CustomRule:
    """Represents a custom detection rule."""
    id: str
    name: str
    description: str
    severity: str  # critical, high, medium, low, info
    category: str
    language: str  # python, javascript, java, go, rust, or 'all'
    
    # Pattern matching
    pattern_type: str  # 'regex', 'ast', or 'combined'
    regex_pattern: Optional[str] = None
    regex_scope: Optional[str] = None  # 'line', 'block', 'file'
    
    # AST pattern (simplified for now)
    ast_node_type: Optional[str] = None
    ast_conditions: Optional[Dict[str, Any]] = None
    
    # Context conditions
    conditions: Dict[str, Any] = field(default_factory=dict)
    
    # False positive filters
    false_positive_filters: List[str] = field(default_factory=list)
    
    # Remediation guidance
    remediation_message: Optional[str] = None
    code_example: Optional[str] = None
    
    # Metadata
    enabled: bool = True
    version: str = "1.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'category': self.category,
            'language': self.language,
            'pattern_type': self.pattern_type,
            'regex_pattern': self.regex_pattern,
            'regex_scope': self.regex_scope,
            'ast_node_type': self.ast_node_type,
            'ast_conditions': self.ast_conditions,
            'conditions': self.conditions,
            'false_positive_filters': self.false_positive_filters,
            'remediation_message': self.remediation_message,
            'code_example': self.code_example,
            'enabled': self.enabled,
            'version': self.version
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CustomRule':
        """Create rule from dictionary."""
        # Handle nested pattern structure from YAML
        if 'pattern' in data:
            pattern_data = data.pop('pattern')
            if isinstance(pattern_data, dict):
                data['pattern_type'] = pattern_data.get('type', 'regex')
                data['regex_pattern'] = pattern_data.get('expression')
                data['regex_scope'] = pattern_data.get('scope', 'line')
        
        # Handle nested remediation structure from YAML
        if 'remediation' in data:
            remediation_data = data.pop('remediation')
            if isinstance(remediation_data, dict):
                data['remediation_message'] = remediation_data.get('message')
                data['code_example'] = remediation_data.get('code_example')
        
        return cls(**data)
    
    def matches_language(self, language: str) -> bool:
        """Check if rule applies to given language."""
        return self.language.lower() == 'all' or self.language.lower() == language.lower()
    
    def is_enabled(self) -> bool:
        """Check if rule is enabled."""
        return self.enabled
    
    def should_skip(self, file_path: str, line_content: str) -> bool:
        """Check if finding should be skipped based on false positive filters."""
        # Check file path patterns
        for pattern in self.false_positive_filters:
            if pattern in file_path:
                return True
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        
        # Check line content patterns
        for pattern in self.false_positive_filters:
            if pattern in line_content:
                return True
            if re.search(pattern, line_content, re.IGNORECASE):
                return True
        
        return False
    
    def check_conditions(self, context: Dict[str, Any]) -> bool:
        """Check if context meets rule conditions."""
        for key, expected_value in self.conditions.items():
            if key not in context:
                return False
            actual_value = context[key]
            
            # Support for list of allowed values
            if isinstance(expected_value, list):
                if actual_value not in expected_value:
                    return False
            elif actual_value != expected_value:
                return False
        
        return True


class CustomRuleEngine:
    """Engine for loading and applying custom rules."""
    
    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules: List[CustomRule] = []
        self.compiled_regexes: Dict[str, Pattern] = {}
        
        if rules_dir:
            self.load_rules_from_dir(rules_dir)
    
    def load_rules_from_dir(self, rules_dir: Path) -> None:
        """Load all YAML rule files from directory."""
        if not rules_dir.exists():
            return
        
        for rule_file in rules_dir.glob("*.yaml"):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_data = yaml.safe_load(f)
                
                if 'rule' in rule_data:
                    rule = CustomRule.from_dict(rule_data['rule'])
                    if rule.is_enabled():
                        self.rules.append(rule)
                        # Pre-compile regex if pattern exists
                        if rule.regex_pattern and rule.pattern_type == 'regex':
                            try:
                                self.compiled_regexes[rule.id] = re.compile(
                                    rule.regex_pattern, 
                                    re.MULTILINE | re.IGNORECASE
                                )
                            except re.error:
                                # Skip invalid regex
                                pass
            except Exception as e:
                # Log error but continue loading other rules
                print(f"Error loading rule {rule_file}: {e}")
    
    def add_rule(self, rule: CustomRule) -> None:
        """Add a rule dynamically."""
        if rule.is_enabled():
            self.rules.append(rule)
            if rule.regex_pattern and rule.pattern_type == 'regex':
                try:
                    self.compiled_regexes[rule.id] = re.compile(
                        rule.regex_pattern,
                        re.MULTILINE | re.IGNORECASE
                    )
                except re.error:
                    pass
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID."""
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                self.rules.pop(i)
                if rule_id in self.compiled_regexes:
                    del self.compiled_regexes[rule_id]
                return True
        return False
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule."""
        for rule in self.rules:
            if rule.id == rule_id:
                rule.enabled = True
                if rule.regex_pattern and rule.pattern_type == 'regex':
                    try:
                        self.compiled_regexes[rule.id] = re.compile(
                            rule.regex_pattern,
                            re.MULTILINE | re.IGNORECASE
                        )
                    except re.error:
                        pass
                return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule."""
        for rule in self.rules:
            if rule.id == rule_id:
                rule.enabled = False
                if rule_id in self.compiled_regexes:
                    del self.compiled_regexes[rule_id]
                return True
        return False
    
    def get_rules_for_language(self, language: str) -> List[CustomRule]:
        """Get all enabled rules for a specific language."""
        return [
            rule for rule in self.rules 
            if rule.is_enabled() and rule.matches_language(language)
        ]
    
    def apply_regex_rules(
        self, 
        source_code: str, 
        language: str,
        file_path: str = ""
    ) -> List[Dict[str, Any]]:
        """Apply regex-based rules to source code."""
        findings = []
        rules = self.get_rules_for_language(language)
        
        for rule in rules:
            if rule.pattern_type != 'regex' or not rule.regex_pattern:
                continue
            
            # Check conditions first
            context = {
                'file_path': file_path,
                'language': language,
                'line_count': len(source_code.splitlines())
            }
            
            if not rule.check_conditions(context):
                continue
            
            # Get compiled regex or compile on the fly
            regex = self.compiled_regexes.get(rule.id)
            if not regex:
                try:
                    regex = re.compile(rule.regex_pattern, re.MULTILINE | re.IGNORECASE)
                except re.error:
                    continue
            
            # Find matches
            for match in regex.finditer(source_code):
                # Get the line content
                lines = source_code[:match.start()].splitlines()
                line_num = len(lines) + 1
                line_content = lines[-1] if lines else ""
                
                # Check false positives
                if rule.should_skip(file_path, line_content):
                    continue
                
                # Create finding
                finding = {
                    'category': rule.category,
                    'severity': rule.severity,
                    'message': rule.description,
                    'line': line_num,
                    'snippet': match.group(0)[:100] + (match.group(0)[100:] and '...'),
                    'recommendation': rule.remediation_message or "Review this code for potential issues.",
                    'rule_id': rule.id,
                    'rule_name': rule.name
                }
                
                if rule.code_example:
                    finding['fix_example'] = rule.code_example
                
                findings.append(finding)
        
        return findings
    
    def apply_ast_rules(
        self,
        ast_tree: Any,
        language: str,
        file_path: str = ""
    ) -> List[Dict[str, Any]]:
        """Apply AST-based rules (placeholder for future implementation)."""
        # This is a simplified version - full AST pattern matching would require
        # a more sophisticated implementation with tree-sitter or similar
        findings = []
        rules = self.get_rules_for_language(language)
        
        for rule in rules:
            if rule.pattern_type != 'ast' or not rule.ast_node_type:
                continue
            
            # For now, we'll just note that AST rules need the AST to be traversed
            # This would be implemented with tree-sitter queries or similar
            pass
        
        return findings
    
    def apply_all_rules(
        self,
        source_code: str,
        language: str,
        ast_tree: Any = None,
        file_path: str = ""
    ) -> List[Dict[str, Any]]:
        """Apply all applicable rules to source code."""
        findings = []
        
        # Apply regex rules
        findings.extend(self.apply_regex_rules(source_code, language, file_path))
        
        # Apply AST rules if AST is provided
        if ast_tree is not None:
            findings.extend(self.apply_ast_rules(ast_tree, language, file_path))
        
        return findings
    
    def list_rules(self) -> List[Dict[str, Any]]:
        """List all rules with their status."""
        return [rule.to_dict() for rule in self.rules]
    
    def get_rule(self, rule_id: str) -> Optional[CustomRule]:
        """Get a specific rule by ID."""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None


# Default rules directory
DEFAULT_RULES_DIR = Path(__file__).parent / "rules"
