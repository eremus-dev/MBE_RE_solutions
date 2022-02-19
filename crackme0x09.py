from pwnlib.tubes.process import process


def main(passw: str) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/crackme0x09', env={"LOL": ""})

    # receive our title
    print(crack.recvline(timeout=1))

    # send our passwords
    passw = bytes(f"{passw}", "utf8")
    crack.sendline(passw)

    # receive our prompt and our praise
    resp = crack.recvline(timeout=1)
    print(f"{passw}:{resp}")


if __name__ == "__main__":
    main(54322)
