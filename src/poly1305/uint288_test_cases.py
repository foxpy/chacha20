from random import randint


def to_le_str(x):
    nums = []
    while x > 0:
        nums.append(x % (2 ** 8))
        x //= (2 ** 8)
    return ", ".join(map(str, nums))


# addition
a = randint(0, 2 ** 288)
b = randint(0, 2 ** 288)
product = (a + b) % (2 ** 288)
print(to_le_str(a))
print("+")
print(to_le_str(b))
print("=")
print(to_le_str(product))
print()

# multiplication
a = randint(0, 2 ** 288)
b = randint(0, 2 ** 288)
product = (a * b) % (2 ** 288)
print(to_le_str(a))
print("*")
print(to_le_str(b))
print("=")
print(to_le_str(product))
print()
