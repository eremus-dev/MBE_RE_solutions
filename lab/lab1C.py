from pwnlib.tubes.process import process


def main(password: str) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/lab1C')

    # receive empty lines
    for i in range(0, 4):
        print(str(crack.recvline(), "utf-8").strip())

    # send our password
    password = bytes(f"{password}", "utf8")
    crack.sendline(password)

    # receive our prompt and our praise or handle exit with wrong answer
    print(str(crack.recvline(), "utf-8").strip())
    print(str(crack.recv(timeout=1), "utf-8").strip())


if __name__ == "__main__":

    password = 5274
    main(password)
