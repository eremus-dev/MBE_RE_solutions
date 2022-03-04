import binascii


def bruteforce() -> None:
    string_parts = ["757c7d51", "67667360", "7b66737e", "33617c7d"]

    string = []
    for i in string_parts:
        y = []
        i = binascii.unhexlify(i)
        y += i
        string += y[::-1]

    for i in range(0, 255):
        output = ''.join([chr(c ^ i) for c in string])
        if output == "Congratulations!":
            print(f"Key: {i} -> {output}")


bruteforce()
