# Modern Binary Exploitation Reversing Solutions

## Intro
To get back into the swing of reversing challenges I'm going to start with CMU's Modern Binary Exploitation reversing challenges.

All the reversing for these challenges happens in Ghidra, all the solutions implemented in python with pwnlib to do the actual interesting work for us.

# Lab 1 crackmes

These are pretty standard (albiet really easy) crackmes they implement some functionality that requires some input to get the correct solution. Lets dive in.

## Crackme00a
#### Reversing - High level Description
Very straight forwards. After navigating to the main function, we can see at 08048501 a prompt for password is printed, "Enter password: ", a string is then read from stdin and stored in the stack and that strcmp on this local string and a string stored in the elf files .data section called pass.1685 that has the value "g00dJ0B!" if the comparison succeeds (returns 0) then the "Congrats!" is printed and the program exits, otherwise the program continues to request the password.

##### Decompilation
```c
int main(void){
  int iVar1;
  int in_GS_OFFSET;
  char local_2d [25];
  int local_14;

  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  while( true ) {
    printf("Enter password: ");
    __isoc99_scanf("%s",local_2d);
    iVar1 = strcmp(pass.1685,local_2d);
    if (iVar1 == 0) break;
    puts("Wrong!");
  }
  puts("Congrats!");
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

#### Solution script

```python
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
```

## Crackme00b

This is identical to the challenge above except expecting a different password, w0wgreat, also stored in the .data section, though this time it is encoded as unicode32 according to Ghidra.

We will skip to implementing the solution script since we already know what is going on.

#### Solution script

```python
from pwnlib.tubes.process import process


def main() -> None:
    # open connection to our challenge binary
    crack = process('./challenges/crackme0x00a')

    # send our password
    crack.sendline(b"w0wgreat")

    # receive our prompt and our praise
    print(crack.recvline(timeout=1))


if __name__ == "__main__":
    main()
```
## Crackme01

#### Reversing - High level Description

This is almost the same as the above two challenges. All of the funcationality is still confined to the main function of the challenge. It still resolves around a password prompt, a scanf function call that will parse a number out of input, and a comparison, this time between the value 0x149a or 5274 in decimal. If 5274 is entered then print Password OK :) or if not then Invalid Password!. Either way the program exits.

##### Decompilation
```c
int main(void){
  int local_8;

  printf("IOLI Crackme Level 0x01\n");
  printf("Password: ");
  scanf("%d",&local_8);
  if (local_8 == 0x149a) {
    printf("Password OK :)\n");
  }
  else {
    printf("Invalid Password!\n");
  }
  return 0;
}
```

#### Solution Script
```python
from pwnlib.tubes.process import process


def main() -> None:
    # open connection to our challenge binary
    crack = process('./challenges/crackme0x01')

    # receive our title
    print(crack.recvline(timeout=1))

    # send our password
    crack.sendline(b"5274")

    # receive our prompt and our praise
    print(crack.recvline(timeout=1))


if __name__ == "__main__":
    main()
```

## Crackme0x02
#### Reversing - High level Description

In this case the decompilation is boring, but the assembly is more interesting.

Here we can see that the number that we are entering is being compared to a number that is being dynamically generated before the comparison. Lets do the operations rather then just relying on Ghidra's amazing decompilation, which solves it for us. After the header and prompt is printed, the call to scanf is prepared, this loads the address of an int on the stack, and a %d format specifier, before calling scanf. The number we enter is then stored on the stack.

The number it is to be compared to is then generated. We load 0x5a and 0x1ec into two locations on the stack. We then add them together after loading one of these values into EDX, yielding 582. This is then timed together, 582 * 582, yielding our password, 338724.

Which when entered gives us the Password OK :) prompt value.

##### Disassembly
```asm
        08048418 8d 45 fc        LEA        EAX=>local_8,[EBP + -0x4]
        0804841b 89 44 24 04     MOV        dword ptr [ESP + local_2c],EAX
        0804841f c7 04 24        MOV        dword ptr [ESP]=>local_30,DAT_0804856c           = 25h    %
                 6c 85 04 08
        08048426 e8 e1 fe        CALL       <EXTERNAL>::scanf                                int scanf(char * __format, ...)
                 ff ff
        0804842b c7 45 f8        MOV        dword ptr [EBP + local_c],0x5a
                 5a 00 00 00
        08048432 c7 45 f4        MOV        dword ptr [EBP + local_10],0x1ec
                 ec 01 00 00
        08048439 8b 55 f4        MOV        EDX,dword ptr [EBP + local_10]
        0804843c 8d 45 f8        LEA        EAX=>local_c,[EBP + -0x8]
        0804843f 01 10           ADD        dword ptr [EAX]=>local_c,EDX
        08048441 8b 45 f8        MOV        EAX=>local_c,dword ptr [EBP + -0x8]
        08048444 0f af 45 f8     IMUL       EAX,dword ptr [EBP + local_c]
        08048448 89 45 f4        MOV        dword ptr [EBP + local_10],EAX
        0804844b 8b 45 fc        MOV        EAX,dword ptr [EBP + local_8]
        0804844e 3b 45 f4        CMP        EAX,dword ptr [EBP + local_10]
        08048451 75 0e           JNZ        LAB_08048461
        08048453 c7 04 24        MOV        dword ptr [ESP]=>local_30,s_Password_OK_:)_080   = "Password OK :)\n"
                 6f 85 04 08
        0804845a e8 bd fe        CALL       <EXTERNAL>::printf                               int printf(char * __format, ...)
                 ff ff
        0804845f eb 0c           JMP        LAB_0804846d
                             LAB_08048461                                    XREF[1]:     08048451(j)
        08048461 c7 04 24        MOV        dword ptr [ESP]=>local_30,s_Invalid_Password!_   = "Invalid Password!\n"
                 7f 85 04 08
        08048468 e8 af fe        CALL       <EXTERNAL>::printf                               int printf(char * __format, ...)
                 ff ff
```


##### Decompilation
```c
int main(void){
  int local_8;

  printf("IOLI Crackme Level 0x02\n");
  printf("Password: ");
  scanf("%d",&local_8);
  if (local_8 == 0x52b24) {
    printf("Password OK :)\n");
  }
  else {
    printf("Invalid Password!\n");
  }
  return 0;
}
```

#### Solution Script

```python
from pwnlib.tubes.process import process


def main() -> None:
    # open connection to our challenge binary
    crack = process('./challenges/crackme0x02')

    # receive our title
    print(crack.recvline(timeout=1))

    # send our password
    crack.sendline(b"338724")

    # receive our prompt and our praise
    print(crack.recvline(timeout=1))


if __name__ == "__main__":
    main()

```

## Crackme0x03
#### Reversing - High level Description

OK, things are starting to get interesting. We've lost the confinement to a single function, in the other cases main. We can now see that main calls test and test calls shift. The uninteresting bit is that test is taking the integer argument from the previous challenge, that is being generated by the same operations.
##### Decompilation
```c
int main(void){
  int local_8;

  printf("IOLI Crackme Level 0x03\n");
  printf("Password: ");
  scanf("%d",&local_8);
  test(local_8,0x52b24);
  return 0;
}
```

But test then performs a comparison and calls shift with either of two strings. Shift starts by getting a string length via strlen call, then iterates through the string performing a transformation upon it.
##### Decompilation
```c
void test(int param_1,int param_2){
  if (param_1 == param_2) {
    shift("Sdvvzrug#RN$$$#=,");
  }
  else {
    shift("Lqydolg#Sdvvzrug$");
  }
  return;
}
```

In this case subtracting 3 from it. We can actually test that this inference is right by performing these operations ourselves.

##### Simple script to test reasoning.
```python
def subtract_three_from_str(string: str) -> str:
    sub = lambda x: chr(ord(x) - 3)
    return "".join(map(sub, list(string)))

print(subtract_three_from_str("Sdvvzrug#RN$$$#=,")) # 'Password OK!!! :)'
print(subtract_three_from_str("Lqydolg#Sdvvzrug$")  #  'Invalid Password!'
```

From this we can see that nothing has really changed, test is ensuring that our input is equal to the generated argument of 338724 and the shift just operates on the error or success messages. We can literally reuse our solution from last challenge.

### Solution Script
```python
from pwnlib.tubes.process import process


def main(x: str) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/crackme0x03')

    # receive our title
    print(crack.recvline(timeout=1))

    # send our password
    crack.sendline(x)

    # receive our prompt and our praise
    print(crack.recvline(timeout=1))


if __name__ == "__main__":
    for i in range(0, 1000):
        main(i)
```

## Crackme0x04
#### Reversing - High level Description

This challenge has the same structure as the proceeding challenge. This script is the first where there are many possible answers. The main function reads a string from stdin and then passes it as an argument to check.

Check is where the password validator logic happens. We can see that the function initialises two variables, which we've renamed accumulator and counter. Counter acts as an index into our string. First the function checks if we counter is past the end of our string and if so prints an error and returns. If we are not a char from our string is converted to a int and summed with the accumulator. If this value ever reaches 0xf or 15 we accept the password. If not yet 15 we continue.

From this we can see that if we ever reach 15 we have a correct password. This means that any string of ints that sum to 15 are correct.  The values provided in the solution script are:
```python
possible = ["1" * 15, "2" * 7 + "1", "12345", "54321", "69", "78", "123456", "789"]
```
The last two 123456 and 789 obviously don't sum to 15, but the password acceptance condition is met regardless.

#### Decomplitation
```c
int main(void){
  char *input;

  printf("IOLI Crackme Level 0x04\n");
  printf("Password: ");
  scanf("%s",&input);
  check(&input);
  return 0;
}

void check(char *param_1){
  size_t size_check;
  char current_val;
  uint counter;
  int accumulator;
  int val_to_int;

  accumulator = 0;                          // sum string into accumulator
  counter = 0;                              // keep track of index into string
  while( true ) {
    size_check = strlen(param_1);
    if (size_check <= counter) {            // ensure we are still within string, if string terminates return error
      printf("Password Incorrect!\n");
      return;
    }
    current_val = param_1[counter];         // get character at index
    sscanf(&current_val,"%d",&val_to_int);  // read from string to int
    accumulator = accumulator + val_to_int; // sum into accumulator
    if (accumulator == 0xf) break;          // if accumulator == 15 the we accept password
    counter = counter + 1;                  // increment counter for next index
  }
  printf("Password OK!\n");
  /* WARNING: Subroutine does not return */
  exit(0);
}
```

#### Solution Script
```python
from time import sleep
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
    possible = ["1" * 15, "2" * 7 + "1", "12345", "54321", "69", "78", "123456", "789"]
    for i in possible:
        main(i)
```