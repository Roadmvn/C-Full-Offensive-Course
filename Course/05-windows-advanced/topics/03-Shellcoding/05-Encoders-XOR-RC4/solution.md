# Solution
```python
key = 0x42
encoded = bytes([b ^ key for b in shellcode])
print(','.join(f'0x{b:02x}' for b in encoded))
```
