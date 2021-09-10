import numpy as np

i = 0
arr = []
while i < 10:
    arr.append(int())
    arr[i] = i + 1
    i = i + 1
i = 0
sum = 0
per = 0
while i < len(arr):
    sum = sum + arr[i]
    print("sum",sum)
    i = i + 1
i = 0
entropy = 0
persum=0
while i < len(arr):
    per = arr[i] / sum
    persum=persum+per
    print("per:",per,"-log(per):",-np.math.log(per))
    entropy = entropy + (per * np.math.log(per))
    print("per", per, "entropy", entropy)
    i = i + 1
print(persum)