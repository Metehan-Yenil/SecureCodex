import json
import subprocess

def run_bandit(code):
    with open("temp_code.py", "w") as f:
        f.write(code)
    cmd = ["bandit", "-f", "json", "temp_code.py"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)  # Bandit çıktısını görüntüle
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}
    
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}

def get_suspicious_lines_with_bandit(code):
    # Bandit sonuçlarını al
    issues = run_bandit(code)
    lines = code.split('\n')
    suspicious = []
    
    # Şüpheli satırları topla
    for issue in issues.get("results", []):
        line_num = issue["line_number"] - 1  # 0-based index
        if line_num < len(lines):
            suspicious_line = lines[line_num].strip()
            suspicious.append(suspicious_line)
    
    return suspicious