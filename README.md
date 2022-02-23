# Modern Binary Exploitation Reversing Challenges Solutions

# Intro
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
#### Reversing - High level Description

Another easy challenge. Just by opening it in a disassmbler we can see that it is not stripped.

```sh
$ file ./challenges/lab1
./challenges/lab1: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.15, BuildID[sha1]=43af309d3735b17cef57f70cb997eebafd17ebf2, not stripped
```

When we navigate to our main, we see that all our program logic is contained inside main (except for a call to some clin functions).

```c
int main(void)

{
  char cVar1;
  int return_val;
  uint uVar2;
  char *pcVar3;
  int in_GS_OFFSET;
  byte bVar4;
  uint index;
  byte password_buf [20];
  int stack_cookie;

  bVar4 = 0;
  stack_cookie = *(int *)(in_GS_OFFSET + 0x14);
  printf("Enter password: ");
  __isoc99_scanf("%s",password_buf);
  index = 0;
  do {
    uVar2 = 0xffffffff;
    pcVar3 = storedpass;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + (uint)bVar4 * -2 + 1;
    } while (cVar1 != '\0');
    if (~uVar2 - 1 <= index) {
      puts("\nSuccess!! Too easy.");
      return_val = 0;
      goto LAB_0804857a;
    }
                    /* this equals '5up3r_DuP3r_u_#_1' */
    if (password_buf[index] != (byte)((byte)index ^ storedpass[index])) {
      puts("Wrong!");
      return_val = 1;
LAB_0804857a:
      if (stack_cookie != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return return_val;
    }
    index = index + 1;
  } while( true );
}
```
We can see that a password prompt is printed and that a string is accepted. There is a variable called storedpass that is clearly being operated on and compared to our input string. Though this is maybe the first function where our decompiler results are less clear then the disassembly.
```c
...
  do {
    uVar2 = 0xffffffff;
    pcVar3 = storedpass;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + (uint)bVar4 * -2 + 1;
    } while (cVar1 != '\0');
    if (~uVar2 - 1 <= index) {
      puts("\nSuccess!! Too easy.");
...
```
This block here mostly relates to a few lines of assembly that are based around the doosy of an instruction SCASB.REPNE This instruction scans the string while each character is not equal to '\0'. This is often used as an odd way of finding string length.
```asm
                             LAB_0804853e                                    XREF[1]:     080484fd(j)
        0804853e 8b 5c 24 20     MOV        EBX,dword ptr [ESP + index]
        08048542 b8 20 a0        MOV        EAX,storedpass       = "5tr0vZBrX:xTyR-P!"
                 04 08
        08048547 c7 44 24        MOV        dword ptr [ESP + local_34],0xffffffff
                 1c ff ff
                 ff ff
        0804854f 89 c2           MOV        EDX,EAX
        08048551 b8 00 00        MOV        EAX,0x0
                 00 00
        08048556 8b 4c 24 1c     MOV        ECX,dword ptr [ESP + local_34]
        0804855a 89 d7           MOV        EDI,EDX
        0804855c f2 ae           SCASB.RE   ES:EDI=>storedpass     = "5tr0vZBrX:xTyR-P!"
        0804855e 89 c8           MOV        EAX,ECX
        08048560 f7 d0           NOT        EAX
        08048562 83 e8 01        SUB        EAX,0x1
        08048565 39 c3           CMP        EBX,EAX
        08048567 72 96           JC         LAB_080484ff
```
If this check fails we jump to a block that performs a byte by byte xor operation and comparison of our storedpass with our entered pass, and if this fails we print a failure message "Wrong" and exit the program.

First things first. Lets compute the correct password. We can see that the password is being xor'd with the index into the password at which the charracter sits.

```asm
                             LAB_080484ff                                    XREF[1]:     08048567(j)
        080484ff 8b 44 24 20     MOV        EAX,dword ptr [ESP + index]
                             this equals '5up3r_DuP3r_u_#_1'
        08048503 05 20 a0        ADD        EAX,storedpass                                   = "5tr0vZBrX:xTyR-P!"
                 04 08
        08048508 0f b6 10        MOVZX      EDX=>storedpass,byte ptr [EAX]                   = "5tr0vZBrX:xTyR-P!"
        0804850b 8b 44 24 20     MOV        EAX,dword ptr [ESP + index]
        0804850f 31 d0           XOR        EAX,EDX
        08048511 88 44 24 27     MOV        byte ptr [ESP + local_29],AL
        08048515 8d 44 24 28     LEA        EAX=>password_buf,[ESP + 0x28]
        08048519 03 44 24 20     ADD        EAX,dword ptr [ESP + index]
        0804851d 0f b6 00        MOVZX      EAX,byte ptr [EAX]
        08048520 3a 44 24 27     CMP        AL,byte ptr [ESP + local_29]
        08048524 74 13           JZ         LAB_08048539
        08048526 c7 04 24        MOV        dword ptr [ESP]=>local_50,s_Wrong!_08048684      = "Wrong!"
                 84 86 04 08
```
We can derive this with some simple python.

```python
    stored_password = "5tr0vZBrX:xTyR-P!"
    decoded_password = []
    for i in range(0, len(stored_password)):
        decoded_password.append(chr(ord(stored_password[i]) ^ i))
    decoded_password = ''.join(decoded_password)
    # 5up3r_DuP3r_u_#_1
```
When we enter this into our program we are greeted with a success message. We can trivially implement this in a solution script.

#### Solution Script
```python
from pwnlib.tubes.process import process


def main(password: str) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/lab1')

    # receive empty lines
    crack.recvline(timeout=1)
    crack.recvline(timeout=1)

    # send our password
    password = bytes(f"{password}", "utf8")
    crack.sendline(password)

    # receive our prompt and our praise or handle exit with wrong answer
    resp = crack.recvline(timeout=1)
    if resp != b'Enter password: Wrong!\n':
        print(resp)
        print(crack.recvline(timeout=1))
    else:
        print(resp)


if __name__ == "__main__":

    # transform the password we found in the binary
    # with the operation we found in the binary
    stored_password = "5tr0vZBrX:xTyR-P!"
    decoded_password = []
    for i in range(0, len(stored_password)):
        decoded_password.append(chr(ord(stored_password[i]) ^ i))
    decoded_password = ''.join(decoded_password)

    main(decoded_password)
```
## Lab 2
#### Reversing - High level Description

We have us a stripped binary. Maybe things are getting more interesting.

```sh
$ file ./challenges/lab2
./challenges/lab2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.15, BuildID[sha1]=b3278fe6368cde1f51b1a491b06b16b162c2adc3, stripped
```

We are going to do our classic first arg to __libc_start_main trick to find our main function. We find this call within our entry function.

```asm
                             undefined entry()
             undefined         AL:1           <RETURN>
             undefined4        Stack[-0x8]:4  local_8                                 XREF[1]:     08048439(*)
                             entry                                           XREF[3]:     Entry Point(*), 08048018(*),
                                                                                          _elfSectionHeaders::00000214(*)
        08048430 31 ed           XOR        EBP,EBP
        08048432 5e              POP        ESI
        08048433 89 e1           MOV        ECX,ESP
        08048435 83 e4 f0        AND        ESP,0xfffffff0
        08048438 50              PUSH       EAX
        08048439 54              PUSH       ESP=>local_8
        0804843a 52              PUSH       EDX
        0804843b 68 90 86        PUSH       FUN_08048690
                 04 08
        08048440 68 20 86        PUSH       FUN_08048620
                 04 08
        08048445 51              PUSH       ECX
        08048446 56              PUSH       ESI
        08048447 68 e9 84        PUSH       FUN_080484e9  <- this be main
                 04 08
        0804844c e8 bf ff        CALL       <EXTERNAL>::__libc_start_main                    undefined __libc_start_main()
                 ff ff
```

One look at our main function and we see some anti-static analysis measures that I initially mistook for anti-debugging measures.

Thankfully the function raises a lot of questions that are answered by the main function.

```c
int main(void){
  code *pcVar1;
  int ret_val;

  signal(5,FUN_080484e4); <- what is this?
  printf("Enter password: "); <- This is a dummy call?
  pcVar1 = (code *)swi(3); <- This is a software interrupt, the same used by debuggers, and will pause our program?
  ret_val = (*pcVar1)(); <- We are calling the signal?
  return ret_val; <- will never be called?
}
```

Since I've already solved this, I can saftely say these questions are a good start but also wrong. So lets answer these initial quesitons, and get to the truth.

### Signal handling?

Signal registers a handler for a given signal. when we look at the docs we see:

```c
       signal - ANSI C signal handling

SYNOPSIS
       #include <signal.h>

       typedef void (*sighandler_t)(int);

       sighandler_t signal(int signum, sighandler_t handler);
```

So for signal 5 we are registering the function FUN_080484e4 (which we will rename to sighandler_nop for obvious reasons). What is signal 5? We can get this from the kill command.
```sh
$ kill -l
 1) SIGHUP       2) SIGINT       3) SIGQUIT      4) SIGILL       5) SIGTRAP
 6) SIGABRT      7) SIGBUS       8) SIGFPE       9) SIGKILL     10) SIGUSR1
11) SIGSEGV     12) SIGUSR2     13) SIGPIPE     14) SIGALRM     15) SIGTERM
16) SIGSTKFLT   17) SIGCHLD     18) SIGCONT     19) SIGSTOP     20) SIGTSTP
21) SIGTTIN     22) SIGTTOU     23) SIGURG      24) SIGXCPU     25) SIGXFSZ
26) SIGVTALRM   27) SIGPROF     28) SIGWINCH    29) SIGIO       30) SIGPWR
31) SIGSYS      34) SIGRTMIN    35) SIGRTMIN+1  36) SIGRTMIN+2  37) SIGRTMIN+3
38) SIGRTMIN+4  39) SIGRTMIN+5  40) SIGRTMIN+6  41) SIGRTMIN+7  42) SIGRTMIN+8
43) SIGRTMIN+9  44) SIGRTMIN+10 45) SIGRTMIN+11 46) SIGRTMIN+12 47) SIGRTMIN+13
48) SIGRTMIN+14 49) SIGRTMIN+15 50) SIGRTMAX-14 51) SIGRTMAX-13 52) SIGRTMAX-12
53) SIGRTMAX-11 54) SIGRTMAX-10 55) SIGRTMAX-9  56) SIGRTMAX-8  57) SIGRTMAX-7
58) SIGRTMAX-6  59) SIGRTMAX-5  60) SIGRTMAX-4  61) SIGRTMAX-3  62) SIGRTMAX-2
63) SIGRTMAX-1  64) SIGRTMAX
```
Okay so we are registering FUN_080484e4 as a signal handler for the SIGTRAP signal call.
```c
void FUN_080484e4(void){
  return;
}
```

So what is SIGTRAP?

```sh
$ man 7 signal
...
 SIGTRAP      P2001      Core    Trace/breakpoint trap
...
```
Ah, a signal that is called by debuggers. At this point I realize that INT3 is not an anti-debugging measure. Which is roughly when I realised there is a heap of instructions below the INT3 instruction, and I remembered INT3 is an anti-static analysis measure used to halt disassembly and that all we need to do is instruct our debugger to diassemble all the data. When our signal handler is called it will immediately return and RIP will execute the next instruction. In otherwords besides the INT3 signal main will behave as a normal function.

So after much ado, here is our challenge function.

```asm
                             **************************************************************
                             *                                                            *
                             *  FUNCTION                                                  *
                             **************************************************************
                             int main(void)
             int               EAX:4          <RETURN>                                XREF[1]:     08048532(W)
             undefined4        EAX:4          ret_val                                 XREF[1]:     08048532(W)
             undefined4        Stack[-0x14]:4 local_14                                XREF[1]:     080484fa(W)
             undefined4        Stack[-0x2c]:4 local_2c                                XREF[1]:     0804851d(W)
             undefined4        Stack[-0x48]:4 local_48                                XREF[1]:     08048509(W)
             undefined4        Stack[-0x4c]:4 local_4c                                XREF[2]:     08048511(*),
                                                                                                   0804852a(*)
                             main                                            XREF[3]:     entry:08048447(*), 0804873c,
                                                                                          080487c0(*)
        080484e9 55              PUSH       EBP
        080484ea 89 e5           MOV        EBP,ESP
        080484ec 57              PUSH       EDI
        080484ed 53              PUSH       EBX
        080484ee 83 e4 f0        AND        ESP,0xfffffff0
        080484f1 83 ec 40        SUB        ESP,0x40
        080484f4 65 a1 14        MOV        EAX,GS:[0x14]
                 00 00 00
        080484fa 89 44 24 3c     MOV        dword ptr [ESP + local_14],EAX
        080484fe 31 c0           XOR        EAX,EAX
        08048500 50              PUSH       EAX
        08048501 31 c0           XOR        EAX,EAX
        08048503 74 03           JZ         LAB_08048508
        08048505 83 c4 04        ADD        ESP,0x4
                             LAB_08048508                                    XREF[1]:     08048503(j)
        08048508 58              POP        EAX
        08048509 c7 44 24        MOV        dword ptr [ESP + local_48],sighandler_nop
                 04 e4 84
                 04 08
        08048511 c7 04 24        MOV        dword ptr [ESP]=>local_4c,0x5
                 05 00 00 00
        08048518 e8 b3 fe        CALL       <EXTERNAL>::signal                               __sighandler_t signal(int __sig,
                 ff ff
        0804851d c7 44 24        MOV        dword ptr [ESP + local_2c],0x0
                 20 00 00
                 00 00
        08048525 b8 f0 86        MOV        EAX,s_Enter_password:_080486f0                   = "Enter password: "
                 04 08
        0804852a 89 04 24        MOV        dword ptr [ESP]=>local_4c,EAX=>s_Enter_passwor   = "Enter password: "
        0804852d e8 8e fe        CALL       <EXTERNAL>::printf                               int printf(char * __format, ...)
                 ff ff
        08048532 cc              INT3
        08048533 b8 01 87        MOV        EAX,DAT_08048701                                 = 25h    %
                 04 08
        08048538 8d 54 24 28     LEA        EDX,[ESP + 0x28]
        0804853c 89 54 24 04     MOV        dword ptr [ESP + 0x4],EDX
        08048540 89 04 24        MOV        dword ptr [ESP],EAX=>DAT_08048701                = 25h    %
        08048543 e8 d8 fe        CALL       <EXTERNAL>::__isoc99_scanf                       undefined __isoc99_scanf()
                 ff ff
        08048548 c7 44 24        MOV        dword ptr [ESP + 0x20],0x0
                 20 00 00
                 00 00
        08048550 eb 66           JMP        LAB_080485b8
                             LAB_08048552                                    XREF[1]:     080485e1(j)
        08048552 cc              INT3
        08048553 8b 44 24 20     MOV        EAX,dword ptr [ESP + 0x20]
        08048557 05 24 a0        ADD        EAX,s_kw6PZq3Zd;ekR[_1_0804a024                  = "kw6PZq3Zd;ekR[_1"
                 04 08
        0804855c 0f b6 18        MOVZX      EBX,byte ptr [EAX]=>s_kw6PZq3Zd;ekR[_1_0804a024  = "kw6PZq3Zd;ekR[_1"
        0804855f 8b 44 24 20     MOV        EAX,dword ptr [ESP + 0x20]
        08048563 8d 48 01        LEA        ECX,[EAX + 0x1]
        08048566 ba 67 66        MOV        EDX,0x66666667
                 66 66
        0804856b 89 c8           MOV        EAX,ECX
        0804856d f7 ea           IMUL       EDX
        0804856f c1 fa 03        SAR        EDX,0x3
        08048572 89 c8           MOV        EAX,ECX
        08048574 c1 f8 1f        SAR        EAX,0x1f
        08048577 29 c2           SUB        EDX,EAX
        08048579 89 d0           MOV        EAX,EDX
        0804857b c1 e0 02        SHL        EAX,0x2
        0804857e 01 d0           ADD        EAX,EDX
        08048580 c1 e0 02        SHL        EAX,0x2
        08048583 89 ca           MOV        EDX,ECX
        08048585 29 c2           SUB        EDX,EAX
        08048587 89 d0           MOV        EAX,EDX
        08048589 31 d8           XOR        EAX,EBX
        0804858b 88 44 24 27     MOV        byte ptr [ESP + 0x27],AL
        0804858f 8d 44 24 28     LEA        EAX,[ESP + 0x28]
        08048593 03 44 24 20     ADD        EAX,dword ptr [ESP + 0x20]
        08048597 0f b6 00        MOVZX      EAX,byte ptr [EAX]
        0804859a 3a 44 24 27     CMP        AL,byte ptr [ESP + 0x27]
        0804859e 74 13           JZ         LAB_080485b3
        080485a0 c7 04 24        MOV        dword ptr [ESP],s_Wrong!_08048704                = "Wrong!"
                 04 87 04 08
        080485a7 e8 44 fe        CALL       <EXTERNAL>::puts                                 int puts(char * __s)
                 ff ff
        080485ac b8 01 00        MOV        EAX,0x1
                 00 00
        080485b1 eb 46           JMP        LAB_080485f9
                             LAB_080485b3                                    XREF[1]:     0804859e(j)
        080485b3 83 44 24        ADD        dword ptr [ESP + 0x20],0x1
                 20 01
                             LAB_080485b8                                    XREF[1]:     08048550(j)
        080485b8 8b 5c 24 20     MOV        EBX,dword ptr [ESP + 0x20]
        080485bc b8 24 a0        MOV        EAX,s_kw6PZq3Zd;ekR[_1_0804a024                  = "kw6PZq3Zd;ekR[_1"
                 04 08
        080485c1 c7 44 24        MOV        dword ptr [ESP + 0x1c],0xffffffff
                 1c ff ff
                 ff ff
        080485c9 89 c2           MOV        EDX,EAX
        080485cb b8 00 00        MOV        EAX,0x0
                 00 00
        080485d0 8b 4c 24 1c     MOV        ECX,dword ptr [ESP + 0x1c]
        080485d4 89 d7           MOV        EDI,EDX
        080485d6 f2 ae           SCASB.RE   ES:EDI=>s_kw6PZq3Zd;ekR[_1_0804a024              = "kw6PZq3Zd;ekR[_1"
        080485d8 89 c8           MOV        EAX,ECX
        080485da f7 d0           NOT        EAX
        080485dc 83 e8 01        SUB        EAX,0x1
        080485df 39 c3           CMP        EBX,EAX
        080485e1 0f 82 6b        JC         LAB_08048552
                 ff ff ff
        080485e7 cc              INT3
        080485e8 c7 04 24        MOV        dword ptr [ESP],s__Success!!_Too_easy._0804870b  = "\nSuccess!! Too easy."
                 0b 87 04 08
        080485ef e8 fc fd        CALL       <EXTERNAL>::puts                                 int puts(char * __s)
                 ff ff
        080485f4 b8 00 00        MOV        EAX,0x0
                 00 00
                             LAB_080485f9                                    XREF[1]:     080485b1(j)
        080485f9 8b 54 24 3c     MOV        EDX,dword ptr [ESP + 0x3c]
        080485fd 65 33 15        XOR        EDX,dword ptr GS:[0x14]
                 14 00 00 00
        08048604 74 05           JZ         LAB_0804860b
        08048606 e8 d5 fd        CALL       <EXTERNAL>::__stack_chk_fail                     undefined __stack_chk_fail()
                 ff ff
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
                             LAB_0804860b                                    XREF[1]:     08048604(j)
        0804860b 8d 65 f8        LEA        ESP,[EBP + -0x8]
        0804860e 5b              POP        EBX
        0804860f 5f              POP        EDI
        08048610 5d              POP        EBP
```

So the decomplition for this is poor (understandably). I think if I was to patch the binary to replace INT3 with a NOP instead it would massively improve the decompilation.  So after changing the assembly and instructing Ghidra to reconstitute the function we get.

```c
int main(void){
  char cVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  int in_GS_OFFSET;
  byte bVar5;
  uint uStack48;
  byte abStack40 [20];
  int local_14;

  bVar5 = 0;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  signal(5,sighandler_nop);
  printf("Enter password: ");
  __isoc99_scanf();
  uStack48 = 0;
  do {
    uVar3 = 0xffffffff;
    pcVar4 = s_kw6PZq3Zd;ekR[_1_0804a024;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + (uint)bVar5 * -2 + 1;
    } while (cVar1 != '\0');
    if (~uVar3 - 1 <= uStack48) {
      puts("\nSuccess!! Too easy.");
      iVar2 = 0;
      goto LAB_080485f9;
    }
    if (abStack40[uStack48] !=
        (byte)((char)(uStack48 + 1) + (char)((int)(uStack48 + 1) / 0x14) * -0x14 ^
              s_kw6PZq3Zd;ekR[_1_0804a024[uStack48])) {
      puts("Wrong!");
      iVar2 = 1;
LAB_080485f9:
      if (local_14 == *(int *)(in_GS_OFFSET + 0x14)) {
        return iVar2;
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    uStack48 = uStack48 + 1;
  } while( true );
}
```
When we have a look we can see that the there is a heap of confusing operations that is likely just the decompiler getting a little overwhelmed. At the heart of it this is almost identical to lab1. The only difference is that intead of the comparison being
```python
password[index] ^ index
```
We have an operation that is
```python
# password[index] ^ (index + 1)
x = "kw6PZq3Zd;ekR[_1"
store = []
for i in range(0, len(x)):
     store.append(chr(ord(x[i]) ^ (i + 1)))
print("".join(store))
# ju5T_w4Rm1ng_UP!
```
One thing is certain the anti-static disassembly did a doozy on both the disassembler though the resulting decompilation isn't too bad.

#### Solution Script
```python
from pwnlib.tubes.process import process


def main(password: str) -> None:
    # open connection to our challenge binary
    crack = process('./challenges/lab2')

    # receive empty lines
    crack.recvline(timeout=1)
    crack.recvline(timeout=1)

    # send our password
    password = bytes(f"{password}", "utf8")
    crack.sendline(password)

    # receive our prompt and our praise or handle exit with wrong answer
    resp = crack.recvline(timeout=1)
    if resp != b'Enter password: Wrong!\n':
        print(resp)
        print(crack.recvline(timeout=1))
    else:
        print(resp)


if __name__ == "__main__":

    # transform the password we found in the binary
    # with the operation we found in the binary
    x = "kw6PZq3Zd;ekR[_1"
    store = []
    for i in range(0, len(x)):
        store.append(chr(ord(x[i]) ^ (i + 1)))
    decoded_password = "".join(store)

    main(decoded_password)
```

## Lab 3
#### Reversing - High level Description

Okay, another stripped challenge.
```sh
$ file ./challenges/lab3
./challenges/lab3: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.15, BuildID[sha1]=bec53100fab355c947ad9d9a8aa8cb27cbdb4ee9, stripped
```
Loading it into the disassembler we see that this is something new. We use our old __libc_start main trick to find main, rename it, and open it.
```c
int main(void){
  if (DAT_0804a034 == DAT_0804a038) {
    printf("%sSuccess!\n\n%s");
  }
  else {
    printf("%sNope!\n\n%s");
  }
  return 0;
}
```
Doesn't seem right. the compared values aren't initialised, and main is accepting no arguments. The reality is that a lot happens before main, we need to check what other functions are being called before main.

Sure enough we can see there are two functions that are being called, via pretty round about means, _INIT_0 and _INIT_1. Both of these perform different functions. _INIT_0 implements our first anti-debugging functionality. There are a couple of ways to subvert this, but the easiest way is to simple not use static analysis like we've been doing.
```asm

                             _INIT_0
        08048687 55              PUSH       EBP
        08048688 89 e5           MOV        EBP,ESP
        0804868a 83 ec 18        SUB        ESP,0x18
        0804868d 50              PUSH       EAX
        0804868e 31 c0           XOR        EAX,EAX
        08048690 74 03           JZ         LAB_08048695
        08048692 83 c4 04        ADD        ESP,0x4
                             LAB_08048695                                    XREF[1]:     08048690(j)
        08048695 58              POP        EAX
        08048696 c7 44 24        MOV        dword ptr [ESP + local_c],0x0
                 0c 00 00
                 00 00
        0804869e c7 44 24        MOV        dword ptr [ESP + local_10],0x0
                 08 00 00
                 00 00
        080486a6 c7 44 24        MOV        dword ptr [ESP + local_14],0x0
                 04 00 00
                 00 00
        080486ae c7 04 24        MOV        dword ptr [ESP]=>local_18,0x0
                 00 00 00 00
        080486b5 e8 c6 fd        CALL       <EXTERNAL>::ptrace                 <- WARNING BELLS
                 ff ff
        080486ba 83 f8 ff        CMP        EAX,-0x1
        080486bd 0f 85 a4        JNZ        LAB_08048867
                 01 00 00

```
Any call to ptrace in a binary is a bit weird. Looking at the manual we can see here from the return type that if Ptrace cannot establish a trace on itself it will execute the rest of the function.
```sh
man ptrace

RETURN VALUE
       On success, the PTRACE_PEEK* requests return the requested data (but see NOTES),  the  PTRACE_SECCOMP_GET_FILTER  request
       returns the number of instructions in the BPF program, and other requests return zero.

       On  error, all requests return -1, and errno is set appropriately.  Since the value returned by a successful PTRACE_PEEK*
       request may be -1, the caller must clear errno before the call, and then check it afterward to determine whether  or  not
       an error occurred.
```
The function itself is great. It just prints **DEBUGGING IS A CRUTCH** and calls exit(0xdead). Quality.
```c
void _INIT_0(void){
  long lVar1;

  lVar1 = ptrace(PTRACE_TRACEME);
  if (lVar1 != -1) {
    return;
  }
  printf("%s######\n");
  puts("#     #  ######  #####   #    #   ####    ####      #    #    #   ####");
  puts("#     #  #       #    #  #    #  #    #  #    #     #    ##   #  #    #");
  puts("#     #  #####   #####   #    #  #       #          #    # #  #  #");
  puts("#     #  #       #    #  #    #  #  ###  #  ###     #    #  # #  #  ###");
  puts("#     #  #       #    #  #    #  #    #  #    #     #    #   ##  #    #");
  puts("######   ######  #####    ####    ####    ####      #    #    #   ####");
  putchar(10);
  putchar(10);
  printf("%s    #     ####\n");
  puts("    #    #");
  puts("    #     ####");
  puts("    #         #");
  puts("    #    #    #");
  puts("    #     ####");
  putchar(10);
  putchar(10);
  puts("   ##");
  puts("  #  #");
  puts(" #    #");
  puts(" ######");
  puts(" #    #");
  puts(" #    #");
  putchar(10);
  putchar(10);
  printf("%s  ####   #####   #    #   #####   ####   #    #\n");
  puts(" #    #  #    #  #    #     #    #    #  #    #");
  puts(" #       #    #  #    #     #    #       ######");
  puts(" #       #####   #    #     #    #       #    #   ###");
  puts(" #    #  #   #   #    #     #    #    #  #    #   ###");
  printf("  ####   #    #   ####      #     ####   #    #   ###%s\n");
                    /* WARNING: Subroutine does not return */
  exit(0xdead);
}
```
Lets talk through the ways to avoid this if we did want to debug our binary. If we remember at the start of this when we called file on our challenge we were told that our binary was dynamically linked. This means that at the first call to any libc function the system linker has to resolve the address of the function. Ptrace is one of those functions. This happens with some linker foo, known as lazy linking, but the long and the short of it is that all functions all call into part of our elf called .plt or the program linkage table. Here there is a function stub.
```asm
                             **************************************************************
                             *                                                            *
                             *  THUNK FUNCTION                                            *
                             **************************************************************
                             thunk long ptrace(__ptrace_request __request, ...)
                               Thunked-Function: <EXTERNAL>::ptrace
                               assume EBX = 0x8049ff4
             long              EAX:4          <RETURN>
             __ptrace_reque    Stack[0x4]:4   __request
                             <EXTERNAL>::ptrace                              XREF[1]:     _INIT_0:080486b5(c)
        08048480 ff 25 20        JMP        dword ptr [-><EXTERNAL>::ptrace]                      long ptrace(__ptrace_request __r
                 a0 04 08
                             -- Flow Override: CALL_RETURN (COMPUTED_CALL_TERMINATOR)
        08048486 68 40 00        PUSH       0x40
                 00 00
        0804848b e9 60 ff        JMP        FUN_080483f0                                          undefined FUN_080483f0()
                 ff ff
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```
This function then consults the .got.plt section or the global offset table program linkage table by jumping into it with the JMP instruction at 08048480. This first call will simply find no address linked to our .got.plt section so will push ptraces offset into the global offset table onto the stack are call the linker to resolve this address for us.
```asm
                             //
                             // .got.plt
                             // SHT_PROGBITS  [0x8049ff4 - 0x804a023]
                             // ram:08049ff4-ram:0804a023
                             //
                             __DT_PLTGOT                                     XREF[2]:     08049f74(*),
                                                                                          _elfSectionHeaders::000003cc(*)
        08049ff4 18 9f 04 08     addr       _DYNAMIC
                             PTR_08049ff8                                    XREF[1]:     FUN_080483f0:080483f0(R)
        08049ff8 00 00 00 00     addr       00000000
                             PTR_08049ffc                                    XREF[1]:     FUN_080483f0:080483f6
        08049ffc 00 00 00 00     addr       00000000
                             PTR_printf_0804a000                             XREF[1]:     printf:08048400
        0804a000 00 b0 04 08     addr       <EXTERNAL>::printf                                    = ??
                             PTR___stack_chk_fail_0804a004                   XREF[1]:     __stack_chk_fail:08048410
        0804a004 04 b0 04 08     addr       <EXTERNAL>::__stack_chk_fail                          = ??
                             PTR_puts_0804a008                               XREF[1]:     puts:08048420
        0804a008 08 b0 04 08     addr       <EXTERNAL>::puts                                      = ??
                             PTR___gmon_start___0804a00c                     XREF[1]:     __gmon_start__:08048430
        0804a00c 0c b0 04 08     addr       __gmon_start__                                        = ??
                             PTR_exit_0804a010                               XREF[1]:     exit:08048440
        0804a010 10 b0 04 08     addr       <EXTERNAL>::exit                                      = ??
                             PTR___libc_start_main_0804a014                  XREF[1]:     __libc_start_main:08048450
        0804a014 14 b0 04 08     addr       <EXTERNAL>::__libc_start_main                         = ??
                             PTR_putchar_0804a018                            XREF[1]:     putchar:08048460
        0804a018 18 b0 04 08     addr       <EXTERNAL>::putchar                                   = ??
                             PTR___isoc99_scanf_0804a01c                     XREF[1]:     __isoc99_scanf:08048470
        0804a01c 1c b0 04 08     addr       <EXTERNAL>::__isoc99_scanf                            = ??
                             PTR_ptrace_0804a020                             XREF[1]:     ptrace:08048480
        0804a020 20 b0 04 08     addr       <EXTERNAL>::ptrace                                    = ??
```
On all subsequent calls to our function the address will be called. So we can jump the gun and patch the table for the ptrace call, to simply immediately return. This will allow us to debug our binary. Or we can nop out the call to ptrace to begin with. Or whatever, doesn't bother us, we aren't going to use a debugger anyway.

Why would we want to you might ask? Because if we set a breakpoint on main, we can simply print the two variables and we have our answer. But too easy.

On to _INIT_1. Turns out this is where almost all the logic happens. At a high level _INIT_1 asks for a last name, makes sure that the name is at least 5 characters lon, then a serial number, which it reads in as an int, then it calculates the serial number for the name. Then it returns.

At which poing the main functions checking of two seemingly global values makes sense. Is our serial number equal to the serial number that is generated from our entered last name. Gotta say, Ghidra translate SCASB.REPNE into the weirdiest C.
```c
{
  char cVar1;
  uint size_check;
  char *pcVar2;
  int in_GS_OFFSET;
  byte bVar3;
  uint index;
  char local_34 [20];
  int local_20;

  bVar3 = 0;
  local_20 = *(int *)(in_GS_OFFSET + 0x14);
  do {
                    /* a size chcek for our string using SCASB.REPNE */
    size_check = 0xffffffff;
    pcVar2 = local_34;
    do {
      if (size_check == 0) break;
      size_check = size_check - 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + (uint)bVar3 * -2 + 1;
    } while (cVar1 != '\0');
    if (4 < ~size_check - 1) {
      printf("Serial:");
                    /* this is an int that is being stored at DAT_0804a034 */
      __isoc99_scanf();
      index = 0;
      do {
                    /* Yet another size check using SCASB.REPNE */
        size_check = 0xffffffff;
        pcVar2 = local_34;
        do {
          if (size_check == 0) break;
          size_check = size_check - 1;
          cVar1 = *pcVar2;
          pcVar2 = pcVar2 + (uint)bVar3 * -2 + 1;
        } while (cVar1 != '\0');
        if (~size_check - 1 <= index) {
          if (local_20 == *(int *)(in_GS_OFFSET + 0x14)) {
            return;
          }
                    /* WARNING: Subroutine does not return */
          __stack_chk_fail();
        }
                    /* Yep another SCASB.REPNE size check
                        */
        size_check = 0xffffffff;
        pcVar2 = local_34;
        do {
          if (size_check == 0) break;
          size_check = size_check - 1;
          cVar1 = *pcVar2;
          pcVar2 = pcVar2 + (uint)bVar3 * -2 + 1;
        } while (cVar1 != '\0');
                    /* Our actual serial number generation operation */
        DAT_0804a038 = (int)local_34[(index - 1) % (~size_check - 1)] ^
                       (int)local_34[index] + DAT_0804a038;
        index = index + 1;
      } while( true );
    }
    printf("Enter last name (5 or more letters):");
    __isoc99_scanf();
  } while( true );
}
```
I'm leaning on comments here, rather then doing the work to clean the decompilation.

Lets implement this in python and generate our serial number.
```c
size_check = 0xffffffff
DAT_0804a038 = (int)local_34[(index - 1) % (~size_check - 1)] ^ (int)local_34[index] + DAT_0804a038;
```
We can see that we are going to iterate through our name, add the charcter at index with our accumulator then xor it with a character from our string at a index that can be derived from
(0xffffffff % size_check) if index == 0 or (index - 1) % size_check

### Solution Script
```python
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
```

# CMU Bomb

So this is a larger crackme, that gamifies RE by structuring it as a bomb deffusing challenge. This challenge was really fun, especially the few phases, and the secret phase.

```sh
$ file challenges/cmubomb
challenges/cmubomb: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.0.0, with debug_info, not stripped
```

We can see that it is dynamically linked and not stripped. When we disassemble it we see there is a main function that has some helper functions that routinely calls the next phase in the chain, from 1 to 6.

```c
int __regparm3 main(int argc,char **argv)

{
  undefined4 uVar1;
  int in_stack_00000004;
  undefined4 *in_stack_00000008;

  if (in_stack_00000004 == 1) {
    infile = stdin;
  }
  else {
    if (in_stack_00000004 != 2) {
      printf("Usage: %s [<input_file>]\n",*in_stack_00000008);
                    /* WARNING: Subroutine does not return */
      exit(8);
    }
    infile = (_IO_FILE *)fopen((char *)in_stack_00000008[1],"r");
    if ((FILE *)infile == (FILE *)0x0) {
      printf("%s: Error: Couldn\'t open %s\n",*in_stack_00000008,in_stack_00000008[1]);
                    /* WARNING: Subroutine does not return */
      exit(8);
    }
  }
  initialize_bomb();
  printf("Welcome to my fiendish little bomb. You have 6 phases with\n");
  printf("which to blow yourself up. Have a nice day!\n");
  uVar1 = read_line();
  phase_1(uVar1);
  phase_defused();
  printf("Phase 1 defused. How about the next one?\n");
  uVar1 = read_line();
  phase_2(uVar1);
  phase_defused();
  printf("That\'s number 2.  Keep going!\n");
  uVar1 = read_line();
  phase_3(uVar1);
  phase_defused();
  printf("Halfway there!\n");
  uVar1 = read_line();
  phase_4(uVar1);
  phase_defused();
  printf("So you got that one.  Try this one.\n");
  uVar1 = read_line();
  phase_5(uVar1);
  phase_defused();
  printf("Good work!  On to the next...\n");
  uVar1 = read_line();
  phase_6(uVar1);
  phase_defused();
  return 0;
}
```
### Phase 1

Phase 1 is trivial as you might expect. When we disassemble it we see there is a direct comparison between a hardcoded sentence "Public speaking is very easy." and the argument that is passed to our the phase 1 function. When we enter this string we move on to the next phase.

```c
void phase_1(undefined4 param_1){
  int iVar1;

  iVar1 = strings_not_equal(param_1,"Public speaking is very easy.");
  if (iVar1 != 0) {
    explode_bomb();
  }
  return;
}
```
So so far we have our solution script as:
```python
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
    ...
```

### Phase 2

Phase two reads 6 numbers from the string that is passed into the phase2 funciton. We can see that the first number has to be 1 and rest have to obey the logic of num[index+1] = (index + 1) * num[index].

```c
void phase_2(undefined4 param_1){
  int iVar1;
  int aiStack32 [7];

  read_six_numbers(param_1,aiStack32 + 1);
  if (aiStack32[1] != 1) {
    explode_bomb();
  }
  iVar1 = 1;
  do {
    if (aiStack32[iVar1 + 1] != (iVar1 + 1) * aiStack32[iVar1]) {
      explode_bomb();
    }
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  return;
}
```

We can generate this with a pretty simply python script.

```py
coll = [1]
    ...: for i in range(1, 6):
    ...:     coll.append((i + 1) * coll[i - 1])
    ...: print(coll)
[1, 2, 6, 24, 120, 720]
```
And our solution script gains a line.

```py
def main() -> None:

    # open our process
    crack = process("./challenges/cmubomb")
...
    # phase 2
    # re'd from phase2
    crack.sendline(b"1 2 6 24 120 720")
    print(str(crack.recvline(), "utf-8"))
    ...
```

### Phase 3

Phase 3 is also pretty straight forward. A string is read in that matches the pattern "%d %c %d". This is then fed into a switch statement. The first integer picks the case 0-7 plus a default. Depending on the case an specific int and character are expected for the next two arguments.
```c
void phase_3(char *param_1){
  int iVar1;
  char cVar2;
  uint local_10;
  char local_9;
  int local_8;

  iVar1 = sscanf(param_1,"%d %c %d",&local_10,&local_9,&local_8);
  if (iVar1 < 3) {
    explode_bomb();
  }
  switch(local_10) {
  case 0:
    cVar2 = 'q';
    if (local_8 != 0x309) {
      explode_bomb();
    }
    break;
  case 1:
    cVar2 = 'b';
    if (local_8 != 0xd6) {
      explode_bomb();
    }
    break;
  case 2:
    cVar2 = 'b';
    if (local_8 != 0x2f3) {
      explode_bomb();
    }
    break;
  case 3:
    cVar2 = 'k';
    if (local_8 != 0xfb) {
      explode_bomb();
    }
    break;
  case 4:
    cVar2 = 'o';
    if (local_8 != 0xa0) {
      explode_bomb();
    }
    break;
  case 5:
    cVar2 = 't';
    if (local_8 != 0x1ca) {
      explode_bomb();
    }
    break;
  case 6:
    cVar2 = 'v';
    if (local_8 != 0x30c) {
      explode_bomb();
    }
    break;
  case 7:
    cVar2 = 'b';
    if (local_8 != 0x20c) {
      explode_bomb();
    }
    break;
  default:
    cVar2 = 'x';
    explode_bomb();
  }
  if (cVar2 != local_9) {
    explode_bomb();
  }
  return;
}
```
We can pick any case but I pick the first one case 0. So our three arguments are "0 q 777". Our solution script gains the line.

```py
def main() -> None:

    # open our process
    crack = process("./challenges/cmubomb")

...

    # phase 3
    # we pick the first switch statement from phase
    crack.sendline(b"0 q 777")
    print(str(crack.recvline(), "utf-8"))
    ...
```

### Phase 4

The forth phase starts to get interesting with the introduction of recursion.

*side note*
It is also where we need to enter the additional password that leads to the secret phase. So if you have read this far (lol) and wonder what is with the string "austinpowers" I'll talk through it when I talk through the secret phase. Though I think I discovered it around the time I completed the first phase, and was exploring the binary.

```c
void phase_4(char *param_1){
  int iVar1;
  int local_8;

  iVar1 = sscanf(param_1,"%d",&local_8);
  if ((iVar1 != 1) || (local_8 < 1)) {
    explode_bomb();
  }
  iVar1 = func4(local_8);
  if (iVar1 != 0x37) {
    explode_bomb();
  }
  return;
}

int func4(int param_1){
  int iVar1;
  int iVar2;

  if (param_1 < 2) {
    iVar2 = 1;
  }
  else {
    iVar1 = func4(param_1 + -1);
    iVar2 = func4(param_1 + -2);
    iVar2 = iVar2 + iVar1;
  }
  return iVar2;
}
```
We can see that we read a single number from our entered string then check that it is greater then 1. If so we call func4, we then check func4 returns 0x37 which is 55.

Func4 returns 1 as a base case and then computes a modified fibonacci sequence. So we need to work our how many summed recursive calls return 9. I did this with a dumb python script. I new that it was going to be a low number, I started summing the fibonacci sequence and realised that computers are good at exactly that.

```py
def recurse(para: int) -> int:
    if para < 2:
        y = 1
    else:
        x = recurse(para - 1)
        y = recurse(para - 2)
        y = x + y
    return y

recurse(9)
# 55
```
Our solution script gains the line

```py
def main() -> None:

    # open our process
    crack = process("./challenges/cmubomb")
...
    # phase 4 and needed password for secret phase
    crack.sendline(b"9 austinpowers")
    print(str(crack.recvline(), "utf-8"))
```

### Phase 5:

Phase 5 is great. Our read in string needs to be length 6. this is then computed as a mapping on the array.123. We can see that our for each index of our string the last byte is & with 16 and this is used to access array.123. This builds another array that must equal the string "giants"

```c
void phase_5(int param_1){
  int iVar1;
  undefined local_c [6];
  undefined local_6;

  iVar1 = string_length(param_1);
  if (iVar1 != 6) {
    explode_bomb();
  }
  iVar1 = 0;
  do {
    local_c[iVar1] = (&array.123)[(char)(*(byte *)(iVar1 + param_1) & 0xf)];
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  local_6 = 0;
  iVar1 = strings_not_equal(local_c,"giants");
  if (iVar1 != 0) {
    explode_bomb();
  }
  return;
}
// array.123 = 'isrveawhobpnutfg'
```

I started at an ascii table for a while, got the feel of it, and then wrote a python program to compute this.

```py
x = 'isrveawhobpnutfg'
for index, letter in enumerate("giants"):
    for i in range(0x61, 0x7A):
        if x[(i) & 0xF] == letter:
            print(f"{index}: {chr(i)} -> {letter}")
# 0: o -> g
# 1: p -> i
# 2: e -> a
# 2: u -> a
# 3: k -> n
# 4: m -> t
# 5: a -> s
# 5: q -> s
```
This gives us our characters to choose (I artificially limited the range of characters with the hope I could spell something funny, but alas).

```py
def main() -> None:

    # open our process
    crack = process("./challenges/cmubomb")
...
    # phase 5
    crack.sendline(b"opekma")
    print(str(crack.recvline(), "utf-8"))
```

### Phase 6:

We get to mess around with data structures from here on in. In this phase a linked list. The decompilation is more complex then the phase. The number one thing to pick up on is the &node pointer.

This implies some kind of graph or tree (a tree is a directed acyclic graph *I known*) or in this case a linked list which is tree with each node having only one child.

```c
void phase_6(undefined4 param_1){
  llist_node *plVar1;
  int iVar2;
  llist_node *plVar3;
  int iVar4;
  llist_node *node_1_ptr;
  llist_node *node_list [6];
  int scanned_numbers [6];

  node_1_ptr = &node1;
  read_six_numbers(param_1,scanned_numbers);
  iVar4 = 0;
  /* ensure numbers aren't repreated, and are between 1 and 6 */
  do {
    iVar2 = iVar4;
    if (5 < scanned_numbers[iVar4] - 1U) {
      explode_bomb();
    }
    while (iVar2 = iVar2 + 1, iVar2 < 6) {
      if (scanned_numbers[iVar4] == scanned_numbers[iVar2]) {
        explode_bomb();
      }
    }
    iVar4 = iVar4 + 1;
  } while (iVar4 < 6);
                    /* create ordered list of nodes, according to input */
  iVar4 = 0;
  do {
    iVar2 = 1;
    plVar3 = node_1_ptr;
    if (1 < scanned_numbers[iVar4]) {
      do {
        plVar3 = (llist_node *)plVar3->child;
        iVar2 = iVar2 + 1;
      } while (iVar2 < scanned_numbers[iVar4]);
    }
    node_list[iVar4] = plVar3;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 6);
  iVar4 = 1;
  plVar3 = node_list[0];
  do {
    plVar1 = node_list[iVar4];
    plVar3->child = (undefined *)plVar1;
    iVar4 = iVar4 + 1;
    plVar3 = plVar1;
  } while (iVar4 < 6);
  plVar1->child = (undefined *)0x0;
  iVar4 = 0;
  do {
    /* Ensure nodes are ordered from highest to lowest */
    if (node_list[0]->value < *(int *)node_list[0]->child) {
      explode_bomb();
    }
    node_list[0] = (llist_node *)node_list[0]->child;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 5);
  return;
}
```

We can see that 6 numbers are read in. The are checked to make sure they are between 1 and 6. That no numbers are repeated. After this the nodes are inserted into an array in the order of the node numbers that we entered.

The nodes are then scanned to ensure that they are ordered highest to lowest. If this succeeds then we are done. We can see from the values below 4, 2, 6, 3, 1, 5 is descending order.

```asm
                             node6
           0804b230 b0 01 00 00     int       1B0h                    value
           0804b234 06 00 00 00     int       6h                      node_number
           0804b238 00 00 00 00     addr      00000000                child

                             node5
        0804b23c d4 00 00        llist_node
                 00 05 00
                 00 00 30
           0804b23c d4 00 00 00     int       D4h                     value
           0804b240 05 00 00 00     int       5h                      node_number
           0804b244 30 b2 04 08     addr      node6                   child

                             node4
        0804b248 e5 03 00        llist_node
                 00 04 00
                 00 00 3c
           0804b248 e5 03 00 00     int       3E5h                    value
           0804b24c 04 00 00 00     int       4h                      node_number
           0804b250 3c b2 04 08     addr      node5                   child

                             node3
        0804b254 2d 01 00        llist_node
                 00 03 00
                 00 00 48
           0804b254 2d 01 00 00     int       12Dh                    value
           0804b258 03 00 00 00     int       3h                      node_number
           0804b25c 48 b2 04 08     addr      node4                   child

                             node2
        0804b260 d5 02 00        llist_node
                 00 02 00
                 00 00 54
           0804b260 d5 02 00 00     int       2D5h                    value
           0804b264 02 00 00 00     int       2h                      node_number
           0804b268 54 b2 04 08     addr      node3                   child


                             node1
        0804b26c fd 00 00        llist_node
                 00 01 00
                 00 00 60
           0804b26c fd 00 00 00     int       FDh                     value
           0804b270 01 00 00 00     int       1h                      node_number
           0804b274 60 b2 04 08     addr      0804b260                child
```

It was really good to play around with Ghidra's ability to define data structures for this. It turned each of these from a collection of 6 bytes into a structured block of data that held references and enabled ghidra to display connections.

Our solution script is almost done now. All the obvious phases are defused. We now just need to explain the secret phase.

```python

def main() -> None:

    # open our process
    crack = process("./challenges/cmubomb")
...
    # phase 6
    crack.sendline(b"4 2 6 3 1 5")
    print(str(crack.recvline(), "utf-8"))
  ...
```

### Secret Phase:

So to find the entry point to the secret phase we need to have a look at the phase_defused function that is called after each of our bomb phases.
```c
void phase_defused(void) {
  int iVar1;
  undefined local_58 [4];
  undefined local_54 [80];

  if (num_input_strings == 6) {
    iVar1 = sscanf(input_strings + 0xf0,"%d %s",local_58,local_54);
    if (iVar1 == 2) {
      iVar1 = strings_not_equal(local_54,"austinpowers");
      if (iVar1 == 0) {
        printf("Curses, you\'ve found the secret phase!\n");
        printf("But finding it and solving it are quite different...\n");
        secret_phase();
      }
    }
    printf("Congratulations! You\'ve defused the bomb!\n");
  }
  return;
}
```

Here we can see that after we have completed all phases if a string is present in one of the entered strings we should enter the secret phase. I'm not going to lie I just addedd the string "austinpowers" after phase 4 because it was an single character. Which we can see the string expects. Turns out it was correct, there is probably a better science available by checking offset into the input strings array.

```c
void secret_phase(void)

{
  undefined4 uVar1;

  uVar1 = read_line();
  iVar2 = __strtol_internal(uVar1,0,10,0);
  if (1000 < iVar2 - 1U) {
    explode_bomb();
  }
  iVar2 = fun7(&n1,iVar2);
  if (iVar2 != 7) {
    explode_bomb();
  }
  printf("Wow! You\'ve defused the secret stage!\n");
  phase_defused();
  return;
}

int fun7(int *param_1,int param_2)

{
  int iVar1;

  if (param_1 == (int *)0x0) {
    iVar1 = -1;
  }
  else if (param_2 < *param_1) {
    iVar1 = fun7(param_1[1],param_2);
    iVar1 = iVar1 * 2;
  }
  else if (param_2 == *param_1) {
    iVar1 = 0;
  }
  else {
    iVar1 = fun7(param_1[2],param_2);
    iVar1 = iVar1 * 2 + 1;
  }
  return iVar1;
}
```
Awesome another recursive function this time involving a data structure which in this case is a sorted binary tree.

I did the whole ghidra datastructures thing to make the tree more legible. We have a root node at n1 all the way down to leaf nodes at n4X. We need to get fun7 to return 7.

```asm
                             n48
        0804b278 e9 03 00        tree_node
                 00 00 00
                 00 00 00
           0804b278 e9 03 00 00     int       3E9h                    val
           0804b27c 00 00 00 00     addr      00000000                child1
           0804b280 00 00 00 00     addr      00000000                child2

                             n46
        0804b284 2f 00 00        tree_node
                 00 00 00
                 00 00 00
           0804b284 2f 00 00 00     int       2Fh                     val
           0804b288 00 00 00 00     addr      00000000                child1
           0804b28c 00 00 00 00     addr      00000000                child2

                             n43
        0804b290 14 00 00        tree_node
                 00 00 00
                 00 00 00
           0804b290 14 00 00 00     int       14h                     val
           0804b294 00 00 00 00     addr      00000000                child1
           0804b298 00 00 00 00     addr      00000000                child2

                             n42
        0804b29c 07 00 00        tree_node
                 00 00 00
                 00 00 00
           0804b29c 07 00 00 00     int       7h                      val
           0804b2a0 00 00 00 00     addr      00000000                child1
           0804b2a4 00 00 00 00     addr      00000000                child2

                             n44
        0804b2a8 23 00 00        tree_node
                 00 00 00
                 00 00 00
           0804b2a8 23 00 00 00     int       23h                     val
           0804b2ac 00 00 00 00     addr      00000000                child1
           0804b2b0 00 00 00 00     addr      00000000                child2

                             n47
        0804b2b4 63 00 00        tree_node
                 00 00 00
                 00 00 00
           0804b2b4 63 00 00 00     int       63h                     val
           0804b2b8 00 00 00 00     addr      00000000                child1
           0804b2bc 00 00 00 00     addr      00000000                child2

                             n41
        0804b2c0 01 00 00        tree_node
                 00 00 00
                 00 00 00
           0804b2c0 01 00 00 00     int       1h                      val
           0804b2c4 00 00 00 00     addr      00000000                child1
           0804b2c8 00 00 00 00     addr      00000000                child2

                             n45
        0804b2cc 28 00 00        tree_node
                 00 00 00
                 00 00 00
           0804b2cc 28 00 00 00     int       28h                     val
           0804b2d0 00 00 00 00     addr      00000000                child1
           0804b2d4 00 00 00 00     addr      00000000                child2

                             n34
        0804b2d8 6b 00 00        tree_node
                 00 b4 b2
                 04 08 78
           0804b2d8 6b 00 00 00     int       6Bh                     val
           0804b2dc b4 b2 04 08     addr      n47                     child1
           0804b2e0 78 b2 04 08     addr      n48                     child2

                             n31
        0804b2e4 06 00 00        tree_node
                 00 c0 b2
                 04 08 9c
           0804b2e4 06 00 00 00     int       6h                      val
           0804b2e8 c0 b2 04 08     addr      n41                     child1
           0804b2ec 9c b2 04 08     addr      n42                     child2

                             n33
        0804b2f0 2d 00 00        tree_node
                 00 cc b2
                 04 08 84
           0804b2f0 2d 00 00 00     int       2Dh                     val
           0804b2f4 cc b2 04 08     addr      n45                     child1
           0804b2f8 84 b2 04 08     addr      n46                     child2

                             n32
        0804b2fc 16 00 00        tree_node
                 00 90 b2
                 04 08 a8
           0804b2fc 16 00 00 00     int       16h                     val
           0804b300 90 b2 04 08     addr      n43                     child1
           0804b304 a8 b2 04 08     addr      n44                     child2

                             n22
        0804b308 32 00 00        tree_node
                 00 f0 b2
                 04 08 d8
           0804b308 32 00 00 00     int       32h                     val
           0804b30c f0 b2 04 08     addr      n33                     child1
           0804b310 d8 b2 04 08     addr      n34                     child2

                             n21
        0804b314 08 00 00        tree_node
                 00 e4 b2
                 04 08 fc
           0804b314 08 00 00 00     int       8h                      val
           0804b318 e4 b2 04 08     addr      n31                     child1
           0804b31c fc b2 04 08     addr      n32                     child2

                             n1
        0804b320 24 00 00        tree_node
                 00 14 b3
                 04 08 08
           0804b320 24 00 00 00     int       24h                     val
           0804b324 14 b3 04 08     addr      n21                     child1
           0804b328 08 b3 04 08     addr      n22                     child2
```

After staring at fun7 for a while what is needed becomes apparent. The tree value is not returned it is just used in a comparison with the value we entered as param2 (which is never changed and always passed to the recursing function). If we need to return 7 we can only do this via getting the correct sequence of return values. In this case
```c
int fun7(int *param_1,int param_2)

{
  int iVar1;

  if (param_1 == (int *)0x0) {
    iVar1 = -1;
  }
  else if (param_2 < *param_1) {
    iVar1 = fun7(param_1[1],param_2);
    iVar1 = iVar1 * 2;
  }
  else if (param_2 == *param_1) {    <- We need to trigger this as our base case
    iVar1 = 0;
  }
  else {
    iVar1 = fun7(param_1[2],param_2); <- Then trigger this 3 times
    iVar1 = iVar1 * 2 + 1;
  }
  return iVar1;
}
```
So we need to enter a value that is bigger then all the other nodes so the else case gets triggered. Then we need 0 to be returned. So we need to enter the largest leaf node value. This will compute
```python
((((0) * 2 + 1) * 2 + 1) * 2 + 1) = 7
```
This means we need to enter the value for N48 which is 0x3E9 or 1001

We are done. This defused the secret stage. The full solution script is below.

#### Solution Script
```python
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

    # secret phase
    crack.sendline(b"1001")
    print(str(crack.recvline(), "utf-8"))
    print(str(crack.recvline(), "utf-8"))
    print(str(crack.recvline(), "utf-8"))


if __name__ == "__main__":
    main()
```

# Bomb

