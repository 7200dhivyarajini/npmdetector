import os
import math
import re

def count_js_files(project_path):
    count = 0
    for root, _, files in os.walk(project_path):
        for f in files:
            if f.endswith(".js"):
                count += 1
    return count


def count_eval_usage(project_path):
    count = 0
    for root, _, files in os.walk(project_path):
        for f in files:
            if f.endswith(".js"):
                try:
                    with open(os.path.join(root, f), "r", errors="ignore") as file:
                        count += file.read().count("eval(")
                except:
                    pass
    return count


def count_child_process_usage(project_path):
    keywords = ["child_process", "exec(", "spawn("]
    count = 0

    for root, _, files in os.walk(project_path):
        for f in files:
            if f.endswith(".js"):
                try:
                    with open(os.path.join(root, f), "r", errors="ignore") as file:
                        content = file.read()
                        for k in keywords:
                            count += content.count(k)
                except:
                    pass
    return count


def count_http_requests(project_path):
    keywords = ["http.request", "https.request", "axios", "fetch("]
    count = 0

    for root, _, files in os.walk(project_path):
        for f in files:
            if f.endswith(".js"):
                try:
                    with open(os.path.join(root, f), "r", errors="ignore") as file:
                        content = file.read()
                        for k in keywords:
                            count += content.count(k)
                except:
                    pass
    return count


def detect_obfuscation(project_path):
    suspicious_patterns = [
        r"\\x[0-9a-fA-F]{2}",
        r"String\.fromCharCode",
        r"atob\(",
        r"eval\("
    ]

    for root, _, files in os.walk(project_path):
        for f in files:
            if f.endswith(".js"):
                try:
                    with open(os.path.join(root, f), "r", errors="ignore") as file:
                        content = file.read()
                        for pattern in suspicious_patterns:
                            if re.search(pattern, content):
                                return 1
                except:
                    pass
    return 0
