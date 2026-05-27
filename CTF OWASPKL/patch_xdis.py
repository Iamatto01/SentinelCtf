import sys

path = r'C:\Users\muham\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages\xdis\unmarshal.py'
with open(path, 'r') as f:
    content = f.read()

# Fix the bug by filtering unhashable types
new_content = content.replace(
    'reference_objects = set(self.intern_objects + self.intern_strings)', 
    'reference_objects = set(x for x in (self.intern_objects + self.intern_strings) if getattr(x, "__hash__", None) is not None)'
)

with open(path, 'w') as f:
    f.write(new_content)
print('Patched xdis!')
