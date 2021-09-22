import os

start = 2600.00
while start>100:
    cut = start*0.108
    start=start-cut
    print("pay:",cut,"left:",start)