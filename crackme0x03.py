from pwnlib.tubes.process import process


def main() -> None:
    # open connection to our challenge binary
    crack = process('./challenges/crackme0x03')

    # receive our title
    print(crack.recvline(timeout=1))

    # send our password
    crack.sendline(b"338724")

    # receive our prompt and our praise
    print(crack.recvline(timeout=1))


if __name__ == "__main__":
    main()
