# Modern Binary Exploitation Solutions

## Intro
To get back into the swing of reversing challenges I'm going to start with CMU's Modern Binary Exploitation reversing challenges and some of the exploit challenges.

All the reversing for these challenges happens in Ghidra, all the solutions implemented in python with pwnlib to do the actual interesting work for us.

# IOLI crackmes

These are pretty standard (albiet really easy) crackmes they implement some functionality that requires some input to get the correct solution. Lets dive in.

## Crackme0x00a
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

## Crackme0x00b

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
## Crackme0x01

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
from pwnlib.tubes.process import process


def main(passw: str) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/crackme0x04')

    # receive our title
    print(crack.recvline(timeout=1))

    # send our passwords
    passw = bytes(f"{passw}", "utf8")
    crack.sendline(passw)

    # receive our prompt and our praise
    resp = crack.recvline(timeout=1)
    print(f"{resp}")


if __name__ == "__main__":
    possible = ["1" * 15, "2" * 7 + "1", "12345", "54321", "69", "78", "123456", "789"]
    for i in possible:
        main(i)
```

## Crackme0x05
#### Reversing - High level Description

The control flow of crackme0x05 is very similar to that of crackme0x04. We still have a main, that accepts a string as an argument and passes it as a parameter to check.
```c
int main(void){
  char input_buff [120];

  printf("IOLI Crackme Level 0x05\n");
  printf("Password: ");
  scanf("%s",input_buff);
  check(input_buff);
  return 0;
}
```
Check then takes our input string and performs the exact same operations as outlined in crackme0x04 with two core differences. The value checked is now 0x10 or 16 instead of 15, and a new function call is now present called parell, this function is called with the argument if the accumulator sums to 16.
```c

void check(char *param_1){
  size_t str_len;
  char curr_char;
  uint index;
  int accumulator;
  int char_val_as_int;

  accumulator = 0;
  index = 0;
  while( true ) {
    str_len = strlen(param_1);
    if (str_len <= index) break;
    curr_char = param_1[index];
    sscanf(&curr_char,"%d",&char_val_as_int);
    accumulator = accumulator + char_val_as_int;
    if (accumulator == 0x10) {
      parell(param_1);
    }
    index = index + 1;
  }
  printf("Password Incorrect!\n");
  return;
}
```
Parell then performs further validation on the string, namely ensuring that the last value present in the string is not an odd number. We can take our solution script from last challenge and alter it so that the string of numbers we are passing in now sum to 16 instead of 15, then we can implement out own filter to ensure that only the positive numbers are passed in to the binary.
```python
possible = [
  "1" * 16, "112345", "961"  # won't work are negative though they sum to 16
  "2" * 8, "1123414", "54322", "682", "88", "952" # will work are positive and sum to 16
]

filter(lambda x: int(x) & 1 == 0, possible)
```
Though any of the numbers that sums to 16 and has an even final number will be accepted and display the output Password: OK!.
```bash
'IOLI Crackme Level 0x05\n'
'22222222':b'Password: Password OK!\n'
'IOLI Crackme Level 0x05\n'
'1123414':b'Password: Password OK!\n'
'IOLI Crackme Level 0x05\n'
'54322':b'Password: Password OK!\n'
'IOLI Crackme Level 0x05\n'
'682':b'Password: Password OK!\n'
'IOLI Crackme Level 0x05\n'
'88':b'Password: Password OK!\n'
'IOLI Crackme Level 0x05\n'
'952':b'Password: Password OK!\n'
```

#### Solution Script
```python
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
    "2" * 8, "1123414", "54322", "682", "88", "952" # will work are positive and sum to 16
    ]
    for i in filter(lambda x: int(x) & 1 == 0, possible):
        main(i)
```

## Crackme0x06
#### Reversing - High level Description

In crackme0x06 we get a new set of functionality that creates a set of abstractions over our crack, and creates another pretty trivial barrier to guessing the password. Our main has one major difference we now have an environment variable being passed to check.
```c
int main(int argc,char *argv,char *envp){  // we now have arguments in main
  char input [120];

  printf("IOLI Crackme Level 0x06\n");
  printf("Password: ");
  scanf("%s",input);
  check(input,envp); // we are passing the arg to check
  return 0;
}
```
In our check function the only difference is that the environment variable is being passed to parell.
```c
void check(char *password,char *env_var){
  size_t string_len;
  char char_store;
  uint index;
  int accumulator;
  int char_to_int;

  accumulator = 0;
  index = 0;
  while( true ) {
    string_len = strlen(password);
    if (string_len <= index) break;
    char_store = password[index];
    sscanf(&char_store,"%d",&char_to_int);
    accumulator = accumulator + char_to_int;
    if (accumulator == 0x10) {
      parell(password,env_var); // the major only difference is that the env_var is being passed to parell
    }
    index = index + 1;
  }
  printf("Password Incorrect!\n");
  return;
}
```
So lets have a look at the parell
```c
void parell(char *password,undefined4 env_var){
  int dummy_check;
  int index;
  uint env_var_pointer;

  sscanf(password,"%d",&env_var_pointer);
  dummy_check = dummy(env_var_pointer,env_var);
  if (dummy_check != 0) {
    for (index = 0; index < 10; index = index + 1) {
      if ((env_var_pointer & 1) == 0) {
        printf("Password OK!\n");
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
    }
  }
  return;
}
```
Here we can see that a pointer to our first environment variable is being passed into a new function called dummy and along with the envp array. That returns and if it is not equal to 0 the old check for odd numbers is performed. However this time it simply checks that there is an even number present in the string, rather then that the last number is even. If so it prints a success prompt and exits the program.
```c
int dummy(int env_var_pointer,char *envp){
  int env_var_ptr;
  int index;

  index = 0;
  do {
                    /* check envp not empty */
    if (*(int *)(envp + index * 4) == 0) {
      return 0;
    }
    env_var_ptr = index * 4;
    index = index + 1;
    env_var_ptr = strncmp(*(char **)(envp + env_var_ptr),"LOLO",3);
  } while (env_var_ptr != 0);
  return 1;
}
```
Here we can see that the environment variable "LOL" is checked for in the envp array. If it is present then strncmp will return 0 and the do-while loop will exit. We should be able to set an env var of LOL and use any of our previously discovered answers.

#### Solution Script
```python
from pwnlib.tubes.process import process


def main(passw: str) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/crackme0x06', env={"LOL": ""})

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
```

## Crackme0x07
#### Reversing - High level Description

Alright our first stripped binary. We know this because we've lost our easy to parse function names and when we check with the command file it is reported as stripped.
```sh
$ file ./challenges/crackme0x07
./challenges/crackme0x07: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.9, stripped
```
Thankfully finding the main function is easy. It is always the last arg placed on the stack to the function __libc_start_main. So we go to our entry point, we look for the call to __libc_start_main and we rename the function pushed onto the stack directly above it to main.
```asm
                             entry                                           XREF[3]:     Entry Point(*), 08048018(*),
                                                                                          _elfSectionHeaders::00000214(*)
        08048400 31 ed           XOR        EBP,EBP
        08048402 5e              POP        ESI
        08048403 89 e1           MOV        ECX,ESP
        08048405 83 e4 f0        AND        ESP,0xfffffff0
        08048408 50              PUSH       EAX
        08048409 54              PUSH       ESP=>local_8
        0804840a 52              PUSH       EDX
        0804840b 68 50 87        PUSH       FUN_08048750
                 04 08
        08048410 68 e0 86        PUSH       FUN_080486e0
                 04 08
        08048415 51              PUSH       ECX
        08048416 56              PUSH       ESI
        08048417 68 7d 86        PUSH       FUN_0804867d                  <- So this must be main
                 04 08
        0804841c e8 67 ff        CALL       <EXTERNAL>::__libc_start_main <- HERE IT IS
                 ff ff
        08048421 f4              HLT
        08048422 90              ??         90h
        08048423 90              ??         90h
```
And sure enough here we are. Crackme0x07, and not much has changed in our main function. All the functions listed have been renamed and as with all the other disassembly has been cleaned up.
```c
int main(int argc,char *argv,char *envp){
  char password_buf [124];

  printf("IOLI Crackme Level 0x07\n");
  printf("Password: ");
  scanf("%s",password_buf);
  check(password_buf,envp);
  return 0;
}
```
We do our normal variable renaming and also rename our check function, which has grown since we saw it last.
```c
void check(char *passwd_buf,char *envp){
  size_t passwrd_len;
  int iVar1;
  char index_char;
  uint pass_index;
  char *accumulator;
  char *char_as_int;

  accumulator = (char *)0x0;
  pass_index = 0;
  while( true ) {
    passwrd_len = strlen(passwd_buf);
    if (passwrd_len <= pass_index) break;
    index_char = passwd_buf[pass_index];
    sscanf(&index_char,"%d",&char_as_int);
    accumulator = accumulator + (int)char_as_int;
    if (accumulator == (char *)0x10) {
      parrel(passwd_buf,envp);
    }
    pass_index = pass_index + 1;
  }
  failure();
                    /* how do we get here? */
  iVar1 = dummy(char_as_int,envp);
  if (iVar1 != 0) {
    for (pass_index = 0; (int)pass_index < 10; pass_index = pass_index + 1) {
      if (((uint)char_as_int & 1) == 0) {
        printf("wtf?\n");
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
    }
  }
  return;
  ```
  Here we can see that the same work occurs in the first half of check. But then after the new call to failure there is a bunch of (unreachable?) code. Lets have a look at the other functions. First we should check parrel.
  ```c
  void parrel(char *password_buf,char *envp){
  int iVar1;
  int local_c;
  char *password_ptr;

  sscanf(password_buf,"%d",&password_ptr);
  iVar1 = dummy(password_ptr,envp);
  if (iVar1 != 0) {
    for (local_c = 0; local_c < 10; local_c = local_c + 1) {
      if (((uint)password_ptr & 1) == 0) {
        if (_global_dummy_check == 1) {
          printf("Password OK!\n");
        }
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
    }
  }
  return;
}
```
We see that we have a new _global variable that is being checked and other then that everything is the same. With dummy we see that the new variable is being set under the same conditions that return 1 (success) from the function
```c
int dummy(char *passwd_ptr,char *envp){
  int index;
  int env_var_ptr;

  index = 0;
  do {
    if (*(int *)(envp + index * 4) == 0) {
      return 0;
    }
    env_var_ptr = index * 4;
    index = index + 1;
    env_var_ptr = strncmp(*(char **)(envp + env_var_ptr),"LOLO",3);
  } while (env_var_ptr != 0);
  _global_dummy_check = 1;
  return 1;
}
```
I guess this means that nothing should change, we pass in our password that sums to 0x10 or 16 and we set our LOL env var and we get our Password OK! prompt. But what is with the dead code?

#### Solution Script
```python
from pwnlib.tubes.process import process


def main(passw: str) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/crackme0x07', env={"LOL": ""})

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
```

## Crackme0x08-9
#### Reversing - High level Description

Not sure what is going on with the higher level challenges. We can see that our eight challenge is not stripped and when we look through the code we see that literally none of the functionality is changed (and that our assumptions from the stripped binary were correct).
```sh
$ file ./challenges/crackme0x08
./challenges/crackme0x08: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.9, not stripped
```
To make matters worse, our solution script from both 6 and 7 work for 8 and 9. I guess we done. 9 is stripped again, but that doesn't really matter. Unless I'm missing something **shrug**

#### Solution Script
```python
from pwnlib.tubes.process import process


def main(passw: str) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/crackme0x08', env={"LOL": ""})

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
```
For crackme0x09 the same is true, except this time it is stripped.

I guess that is done for these IOLI crackmes.

# The Lab crackmes

## Lab 1