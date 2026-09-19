import subprocess, sys
subprocess.run([sys.executable, "-m", "app.main", "drift"], check=True)
print("\n--- DRY RUN REMEDIATION ---\n")
subprocess.run([sys.executable, "-m", "app.main", "heal", "--dry-run"], check=True)
