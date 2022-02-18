from pwnlib.tubes.process import process


def main(passw: str) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/crackme0x04')

    # receive our title
    print(crack.recvline(timeout=1))

    # send our passwords
    passw = bytes(f"{passw}", "utf8")
    # send our passwords
    crack.sendline(passw)

    # receive our prompt and our praise
    resp = crack.recvline(timeout=1)
    print(f"{resp}")


if __name__ == "__main__":
    possible = ["1" * 15, "2" * 7 + "1", "12345", "54321", "69", "78"]
    for i in possible:
        main(i)
