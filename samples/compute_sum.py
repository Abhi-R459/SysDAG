#!/usr/bin/env python3
# compute_sum.py - CPU task then write a benign result
s = sum(range(1, 100000))
with open("/guest/www/result.txt", "w") as f:
    f.write(str(s) + "\n")
print("done")
