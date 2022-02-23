from pwnlib.tubes.process import process


def main() -> None:

    # open bomb print menu
    bomb = process('./challenges/bomb')
    get_header(bomb)

    # Defuse yellow phase
    bomb.sendline(b"1")
    bomb.sendline(b"84371065")
    bomb.sendline(b"\n")
    get_line(bomb, 1)
    get_header(bomb)

    # Defuse green phase
    bomb.sendline(b"2")
    bomb.sendline(b"dcaotdae" + b"\x00" * 6)
    bomb.sendline(b"\n")
    get_line(bomb, 2)
    get_header(bomb)

    # Defuse blue phase
    bomb.sendline(b"3")
    bomb.sendline(b"LLRR")
    bomb.sendline(b"\n")
    get_line(bomb, 2)
    get_header(bomb)

    bomb.sendline(b'4')
    bomb.sendline(b'KDG3DU32D38EVVXJM64\n')
    bomb.sendline(b"\n")
    get_line(bomb, 3)
    get_header(bomb)

    bomb.sendline(b"DISARM")
    print(str(bomb.recvall(), "utf-8"))


def get_line(bomb, count: int):
    for i in range(0, count):
        output = str(bomb.recvline(), "utf-8").strip('\n')
        if DEBUG:
            print(output)


def get_header(bomb):
    for i in range(0, 13):
        output = str(bomb.recvline(), "utf-8").strip('\n')
        print(output)


if __name__ == '__main__':
    DEBUG = True
    main()
