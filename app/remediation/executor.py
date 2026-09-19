import ast
import json
from pathlib import Path

ALLOWED_CALLS = {"revoke_security_group_ingress"}

class SafeExecutor:
    def __init__(self, dry_run=True):
        self.dry_run = dry_run

    def validate(self, code: str):
        tree = ast.parse(code, mode="exec")
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef,
                                 ast.With, ast.Try, ast.Lambda, ast.Attribute)):
                # Attribute is allowed only as ec2.revoke... and is checked below.
                if isinstance(node, ast.Attribute):
                    if not (isinstance(node.value, ast.Name)
                            and node.value.id == "ec2"
                            and node.attr in ALLOWED_CALLS):
                        raise ValueError("Unsafe attribute detected")
                else:
                    raise ValueError("Unsupported AST node detected")
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
        if len(calls) != 1:
            raise ValueError("Exactly one remediation call is required")
        call = calls[0]
        if not (isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.id == "ec2"
                and call.func.attr in ALLOWED_CALLS):
            raise ValueError("Remediation operation is not allow-listed")
        return tree

    def execute_mock(self, code: str):
        self.validate(code)
        if self.dry_run:
            return {"status": "DRY_RUN", "message": "Validated; no state changed."}
        return {"status": "EXECUTED", "message": "Mock remediation accepted."}
