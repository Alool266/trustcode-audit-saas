# Test Python file with deliberate issues
import os
import pickle

# Hardcoded secret
API_KEY = "sk-1234567890abcdef"

# Empty except block
try:
    result = os.system("ls")
except:
    pass

# Using eval
user_input = "print('hello')"
eval(user_input)

# Unsafe deserialization
data = pickle.loads(some_bytes)

# Magic number
if value > 42:
    do_something()
