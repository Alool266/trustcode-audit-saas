"""
Sample Python code with deliberate AI hallucinations for testing.
This file contains various issues that the audit engine should detect.
"""

import pandas as pd
import numpy as np
import os

# Hallucination 1: Non-existent pandas method
def load_data_fast():
    """This uses a hallucinated pandas method."""
    data = pd.read_csv_fast('data.csv')  # Should be read_csv
    return data

# Hallucination 2: Empty except block (silent failure)
def risky_operation():
    """Silently catches and ignores all errors."""
    try:
        result = 10 / 0
    except:  # Empty except - BAD
        pass
    return result

# Hallucination 3: Hardcoded secret
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"  # Should use env vars

def authenticate():
    """Uses hardcoded API key."""
    return API_KEY

# Hallucination 4: O(n²) nested loop (performance risk)
def find_duplicates_slow(items):
    """Inefficient O(n²) duplicate detection."""
    duplicates = []
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            if items[i] == items[j]:
                duplicates.append(items[i])
    return duplicates

# Hallucination 5: Magic number
def calculate_tax(income):
    """Uses unexplained magic number."""
    tax = income * 0.23  # Why 0.23? Should be TAX_RATE constant
    return tax

# Hallucination 6: Bare except (catches everything including SystemExit)
def dangerous_wrapper():
    """Bare except is dangerous."""
    try:
        import some_module
    except:  # Catches SystemExit, KeyboardInterrupt - BAD
        print("Something went wrong")

# Hallucination 7: Another non-existent numpy method
def create_matrix():
    """Uses hallucinated numpy method."""
    matrix = np.zeros_fast((100, 100))  # Should be np.zeros
    return matrix

# Hallucination 8: eval usage (security risk)
def process_user_input(user_input):
    """Dangerous eval usage."""
    result = eval(user_input)  # CRITICAL security issue
    return result

# Good code example (should not trigger)
def proper_error_handling():
    """This is good practice."""
    try:
        with open('file.txt', 'r') as f:
            content = f.read()
    except FileNotFoundError as e:
        print(f"File not found: {e}")
    return content

if __name__ == "__main__":
    print("Sample code loaded.")