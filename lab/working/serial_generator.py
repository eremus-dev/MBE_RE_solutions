#   computed_serial = ((int)username[3] ^ 0x1337U) + 0x5eeded;
#   for (i = 0; i < (int)length; i = i + 1) {
#     if (username[i] < ' ') {
#       return 1;
#     }
#     computed_serial = computed_serial + ((int)username[i] ^ computed_serial) % 0x539;
#   }
#   if (serial_num == computed_serial) {
#     ret_val = 0;
#   }

def generate_serial(username: str) -> int:
    acc = (ord(username[3]) ^ 0x1337) + 0x5eeded

    for i in range(0, len(username)):
        acc += (ord(username[i]) ^ acc) % 0x539

    return acc


name = input("Enter username: ")
print(generate_serial(name))
