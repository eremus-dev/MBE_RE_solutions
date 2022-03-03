from pwnlib.tubes.process import process


def main(password: str) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/lab2')

    # receive empty lines
    crack.recvline(timeout=1)
    crack.recvline(timeout=1)

    # send our password
    password = bytes(f"{password}", "utf8")
    crack.sendline(password)

    # receive our prompt and our praise or handle exit with wrong answer
    resp = crack.recvline(timeout=1)
    if resp != b'Enter password: Wrong!\n':
        print(resp)
        print(crack.recvline(timeout=1))
    else:
        print(resp)


if __name__ == "__main__":

    # transform the password we found in the binary
    # with the operation we found in the binary
    x = "kw6PZq3Zd;ekR[_1"
    store = []
    for i in range(0, len(x)):
        store.append(chr(ord(x[i]) ^ (i + 1)))
    decoded_password = "".join(store)

    main(decoded_password)
