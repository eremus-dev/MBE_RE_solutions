from pwnlib.tubes.process import process


def main() -> None:

    # open our process
    crack = process("./challenges/cmubomb")

    # recieve header
    print(str(crack.recvline(), "utf-8").strip())
    print(str(crack.recvline(), "utf-8"))

    # phase 1
    # hardcoded in phase 1
    crack.sendline(b"Public speaking is very easy.")
    print(str(crack.recvline(), "utf-8"))

    # phase 2
    # re'd from phase2
    crack.sendline(b"1 2 6 24 120 720")
    print(str(crack.recvline(), "utf-8"))

    # phase 3
    # we pick the first switch statement from phase
    crack.sendline(b"0 q 777")
    print(str(crack.recvline(), "utf-8"))

    # phase 4 and needed password for secret phase
    crack.sendline(b"9 austinpowers")
    print(str(crack.recvline(), "utf-8"))

    # phase 5
    crack.sendline(b"opekma")
    print(str(crack.recvline(), "utf-8"))

    # phase 6
    crack.sendline(b"4 2 6 3 1 5")
    print(str(crack.recvline(), "utf-8"))


if __name__ == "__main__":
    main()
