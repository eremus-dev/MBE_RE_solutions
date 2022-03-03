from pwnlib.tubes.process import process


def main(name: str, serial: int) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/lab3')

    # send our password
    name = bytes(f"{name}", "utf8")
    crack.sendline(name)

    # prompt for serial
    serial = bytes(f"{serial}", "utf8")
    crack.sendline(serial)

    # receive answer
    print(str(crack.recvline(timeout=1), "utf-8"))


def serial_gen(name: str) -> int:
    acc = 0
    name = list(name)
    name_len = len(name)
    for index, char in enumerate(name):
        index = 0xffffffff if index == 0 else index-1
        acc = ord(name[index % (name_len)]) ^ ord(char) + acc
    return acc


if __name__ == "__main__":
    # get our name generate our serial number
    name = input("Enter name: ").strip('\n')
    serial = serial_gen(name)

    main(name, serial)
