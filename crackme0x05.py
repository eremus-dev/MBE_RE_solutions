from pwnlib.tubes.process import process


def main(passw: str) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/crackme0x05')

    # receive our title
    print(crack.recvline(timeout=1))

    # send our passwords
    passw = bytes(f"{passw}", "utf8")
    crack.sendline(passw)

    # receive our prompt and our praise
    resp = crack.recvline(timeout=1)
    print(f"{passw}:{resp}")


if __name__ == "__main__":
    possible = [
        "1" * 16, "112345", "961",  # won't work are negative though they sum to 16
        # will work are positive and sum to 16
        "2" * 8, "1123414", "54322", "682", "88", "952"
    ]
    for i in filter(lambda x: int(x) & 1 == 0, possible):
        main(i)
