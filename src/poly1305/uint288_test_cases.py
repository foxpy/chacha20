from random import randint


def to_le_str(a):
    nums = []
    while a > 0:
        nums.append(a % (2 ** 8))
        a //= (2 ** 8)
    return ", ".join(map(str, nums))


a = randint(0, 2 ** 288)
b = randint(0, 2**288)
product = (a + b) % (2 ** 288)
print(to_le_str(a))
print("+")
print(to_le_str(b))
print("=")
print(to_le_str(product))
