from pwnlib.tubes.process import process


def main(username: str, serial: int) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/lab1A')

    # receive header
    for i in range(0, 6):
        print(str(crack.recvline(), "utf-8").strip())

    # send our username
    username = bytes(f"{username}", "utf8")
    crack.sendline(username)

    # receive serial header
    for i in range(0, 5):
        print(str(crack.recvline(), "utf-8").strip())

    # send our serial
    serial = bytes(f"{serial}", "utf8")
    crack.sendline(serial)

    # receive authentication message
    print(str(crack.recvline(), "utf-8").strip())


if __name__ == "__main__":

    username = "eremus"
    serial = 6232823
    main(username, serial)
