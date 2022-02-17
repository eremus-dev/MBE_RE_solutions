from pwnlib.tubes.process import process


def main() -> None:
    # open connection to our challenge binary
    crack = process('./challenges/crackme0x00a')

    # send our password
    crack.sendline(b"g00dJ0B!")

    # receive our prompt and our praise
    print(crack.recvline(timeout=1))


if __name__ == "__main__":
    main()
