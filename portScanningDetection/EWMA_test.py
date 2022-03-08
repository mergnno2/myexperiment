# this file aims to test the EWMA algorithm using simple sequence of digital number.
import random
import matplotlib.pyplot as plt

numbers = []
ewma = []
numbers.append(0)
ewma.append(0)
alpha = 0.01
for i in range(1, 100):
    numbers.append(random.randint(numbers[i - 1] - 5, numbers[i - 1] + 5))
    ewma.append((1 - alpha) * ewma[i - 1] + alpha * numbers[i])
plt.plot(numbers)
plt.plot(ewma)
#print(numbers)
#print(ewma)
plt.show()
