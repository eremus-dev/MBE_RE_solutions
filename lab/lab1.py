from pwnlib.tubes.process import process


def main(password: str) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/lab1')

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
    stored_password = "5tr0vZBrX:xTyR-P!"
    decoded_password = []
    for i in range(0, len(stored_password)):
        decoded_password.append(chr(ord(stored_password[i]) ^ i))
    decoded_password = ''.join(decoded_password)

    main(decoded_password)
