# Work performed - Week #6

# CTF

The goal of the week 5 CTFs is to exploit the format string vulnerabilities.

## Week 6 - Challenge 1

Looking at the `main.c` program, we can see that the flag is in a global variable, so our goal is to find out what is the value of that variable. The vulnerability is on the `printf(buffer)` statement, because the user input is evaluated as a format string, allowing it to execute code, read the stack, or cause a segmentation fault in the program.

<figure align="center">
  <img src="/images/week6/ctf1_1.png" alt="my alt text"/>
  <figcaption>Figure 1. main.c program.</figcaption>
</figure>

First, we need to find the address of the `flag` global variable. To do that, we used the following command:

<figure align="center">
  <img src="/images/week6/ctf1_2.png" alt="my alt text"/>
  <figcaption>Figure 2. objdump command execution.</figcaption>
</figure>

`objdump` is a command-line tool that displays information from object files. The `-t` option specifies that we want to print the symbol table entries of the program, and `| grep flag` part of the command filters the output of the `objdump` command, so that we can see the address of the global variable `flag`. As we can see in the output of the command, the address of our target variable is `0x0804c060`.

Another way of finding out the address of the global variable is to use the gdb. The provided exploit python script has a `pause()` statement, which allows us to use gdb to attach to the process. 

<figure align="center">
  <img src="/images/week6/ctf1_3.png" alt="my alt text"/>
  <figcaption>Figure 3. Provided exploit script.</figcaption>
</figure>

Running the script, we can see the `pid` of the process:

<figure align="center">
  <img src="/images/week6/ctf1_4.png" alt="my alt text"/>
  <figcaption>Figure 4. Execution of the provided script.</figcaption>
</figure>

The provided `pid` will be used to start the gdb program in the desired process: 

<figure align="center">
  <img src="/images/week6/ctf1_5.png" alt="my alt text"/>
  <figcaption>Figure 5. gdb execution.</figcaption>
</figure>

With the gdb running, we write the command `x flag` to find out the address of the`flag` variable.

Lastly, we adapted the provided exploit python script to build our format string.

<figure align="center">
  <img src="/images/week6/ctf1_6.png" alt="my alt text"/>
  <figcaption>Figure 6. Exploit script.</figcaption>
</figure>


The input of the program, which is interpreted as a format string, is the following (but in bytes):

```
0x0804c060%s
```

As there's not offset between the argument pointer and the format string, this will cause the program to print out the value of the variable that is located in the provided address, giving us the value of the flag.

<figure align="center">
  <img src="/images/week6/ctf1_7.png" alt="my alt text"/>
  <figcaption>Figure 7. Execution of the exploit script.</figcaption>
</figure>

## Week 6 - Challenge 2

The second challenge of the week is a little bit more tricky. While in the first one we had to read the value of an address, in this one we need to write to an address.

In the program, the `key` variable has the value `0`. We can also observe that there is a command that gives access to a bash terminal, but the only way to reach that statement is if the `if(key == 0xbeef)` condition evaluates to true. With that said, we know that we need to somehow modify the value of the `key` variable to `0xbeef`. To do that, we need to take advantage of the format string vulnerability of the `printf(buffer)` statement. As in the previous challenge, it is up to the user to provide the format string of the `printf`, allowing it to do unexpected things, such as read from or write to the stack, or even to a specific address.

<figure align="center">
  <img src="/images/week6/ctf2_1.png" alt="my alt text"/>
  <figcaption>Figure 8. main.c program.</figcaption>
</figure>

First, we need to find the address of the `key` global variable. We used the `objdump` utility like in the previous challenge, and found out that the address of our target variable is `0x0804c034`.

<figure align="center">
  <img src="/images/week6/ctf2_2.png" alt="my alt text"/>
  <figcaption>Figure 9. objdump execution.</figcaption>
</figure>

The next step was to build the exploit python script:

<figure align="center">
  <img src="/images/week6/ctf2_3.png" alt="my alt text"/>
  <figcaption>Figure 10. Exploit script.</figcaption>
</figure>

The `%n` format specifier writes the number of characters printed so far to a pointer, which is passed as an argument of the `printf` function. If no corresponding argument is available, as in this case, the program will overwrite the content of the address passed in the format string with the number of characters written. If we want to write a value larger than the number of characters written, we can specify a certain width, which will add a certain number of leading zeros, with the `%.<width>d%n` specifier.

So, as in the previous example, there's no offset between the argument pointer and the format string. We start by adding 4 random bytes so that later on we can write the number of bytes we want to the address of the key variable. Knowing that, we need to build our format string with that address that we want to overwrite, and then use the `%.<width>d%n` specifier to write the desired value to the target variable. First, we converted `0xbeef` from hexadecimal to decimal, which is 48879. Counting the initial 4 characters, plus the size of the address in bytes, we know that to write 48879 (`0xbeef`) characters, we need to write 48871 (48879 - 4 - 4) more bytes. So that's the value of `<width>`.

Executing the script:

<figure align="center">
  <img src="/images/week6/ctf2_4.png" alt="my alt text"/>
  <figcaption>Figure 11. Exploit script execution.</figcaption>
</figure>


<figure align="center">
  <img src="/images/week6/ctf2_5.png" alt="my alt text"/>
  <figcaption>Figure 12. Flag extraction.</figcaption>
</figure>


There was also another possibility that would give us the flag and does not need the first 4 random bytes. In the previous solution we always move the argument pointer of the printf function incremently. But that isn't always necessary. For the content of the `sendline()` we could also use:

```python
(addr).to_bytes(4, byteorder='little') + b"%.48875x%1$n"
```

The difference here is the `%1$n` part that allows us to move the AP pointer to its first position, which corresponds to the provided key variable address, and write 48879 bytes to it.

This gives us the access to a shell. Listing all the files on the current directory with the `ls` command, we can see that there is a `flag.txt` file. Printing the content of the file gives us the flag.


# SEED Lab Tasks

This week's suggested lab was Format String Attack Lab, from SEED labs, with the intent of providing us a better understanding of the C functions that use format strings and what can be done to exploit their vulnerability (format string vulnerability).

## Task 1

After setting up the server using the provided docker-compose configurations, we modified the ´build_string.py´ script to input a format string to the server. This string must crash the server program upon the use of the `myprintf()` function.

```c
void myprintf(char *msg)
{
    // not relevant...

    // This line has a format-string vulnerability
    printf(msg);

    // not relevant...

}
```

As the `printf` function is called in the `myprintf` function without any arguments except the format string, we can use this to input a format string that will try to read an argument. Consequently, as no arguments are provided, it will get data from the stack up from the `printf()`'s internal pointer, where the arguments should have been.


<figure align="center">
  <img src="/images/week6/task1_3.png" alt="my alt text"/>
  <figcaption>Figure 13. Stack disposition.</figcaption>
</figure>

When a format string like "Hello World %s%s%s%s" is provided to the `printf()` function, it will interpret each "%s" as a pointer to a string in the stack. 
So if we send a string of maximum size (1500 bytes, in this case) containing only "%s", eventualy the content in the stack will be an invalid string pointer, causing the program to crash. And we can be completely sure about that because in the `dummy_function` a variable of 100 bytes is set to zero. So, when going through all the `%s` in the format string, eventually we will try to access the zero address and consequently the program will crash.

```python
content = b"%s" * int(1500/2)
```

<figure align="center">
  <img src="/images/week6/task1_1.png" alt="my alt text"/>
  <figcaption>Figure 14. Sending input from file.</figcaption>
</figure>

<figure align="center">
  <img src="/images/week6/task1_2.png" alt="my alt text"/>
  <figcaption>Figure 15. Server crash after input.</figcaption>
</figure>


## Task 2

In this task, we make use of the format string manipulation to print data from the memory on the server side.

### Task 2.A

The goal in the first section of this task is to print the first four bytes of our input (format string).
The use of the `%x` format specifier in `printf()` represents an unsigned hexadecimal integer. As no arguments are provided when calling the function, the use of this specifier will cause the function to directly print the content in the stack as hexadecimal integers.

As we know that the format string is stored in the stack somewhere above the initial `printf()` pointer, we can set an input containing 4 easily identifiable characters and fill the rest of the input with `%x` specifiers. This way, we can identify where the format string is located in the stack by spotting the 4 characters in the `printf()` function output.

<figure align="center">
  <img src="/images/week6/task2A_1.png" alt="my alt text"/>
  <figcaption>Figure 16. Stack on printf </figcaption>
</figure>

To make the display easier to read, we use `%.8x` instead of `%x`. This will assure that every address' content in the stack will be displayed using 8 characters.

```python
content[0:4] = str.encode("AAAA")
fmt = b"%.8x-" * int(1496/5)
content[4:4+len(fmt)] = fmt
```

<figure align="center">
  <img src="/images/week6/task2A_2.png" alt="my alt text"/>
  <figcaption>Figure 17. First 4 bytes of input on output </figcaption>
</figure>

By observing the output, we can identify the 4 "A" characters we sent in the start of the input string, that should be displayed as `0x414141` when converted to hexadecimal (highlighted in yellow).

We can then conclude that there are **63** addresses in the stack between the starting point of the `printf()` function and the format string.

So if we change our input:

```python
content[0:4] = str.encode("AAAA")
fmt = b"%.8x-" * 64
content[4:4+len(fmt)] = fmt
```

the last value displayed will be the first 4 bytes of the input string.

<figure align="center">
  <img src="/images/week6/task2A_3.png" alt="my alt text"/>
  <figcaption>Figure 18. First 4 bytes of input on output </figcaption>
</figure>


### Task 2.B

In this step, we must print the content of a string (secret message) that is located in an address given in the server printout.

<figure align="center">
  <img src="/images/week6/task2B_1.png" alt="my alt text"/>
  <figcaption>Figure 19. Secret message's address </figcaption>
</figure>

As we know how to access the first four bytes of our input [Task 2.A](#task2.a), we can use this to access the content of the string.

And, as it was said before in [Task1](#task1), when given a `%s` specifier, `printf()` will interpret the content in the stack as a pointer to a string.

Having these points in consideration, we can set the first 4 bytes of the input as the address of the secret message, forward the function pointer (using `%x` 63 times) and then use `%s`. By doing this, the function will read the address of the secret message as a string pointer and print it.


```python
secret_message_add = 0x080b4008

content[0:4] = (secret_message_add).to_bytes(4,byteorder="little")
fmt = b"%x" * 63 + b"%s"
content[4:4+len(fmt)] = fmt
```

Or

```python
secret_message_add = 0x080b4008

content[0:4] = (secret_message_add).to_bytes(4,byteorder="little")
fmt = b"%64$s"
content[4:4+len(fmt)] = fmt

```

<figure align="center">
  <img src="/images/week6/task2B_2.png" alt="my alt text"/>
  <figcaption>Figure 20. Printing secret message </figcaption>
</figure>

## Task 3

The goal of this task is, after learning how to access and read data from the memory, to also learn how to modify the server program's memory.

### Task 3.A

Firstly, we want to change the value of `target` variable to any other different value. The address of the variable is given in the server printout:

<figure align="center">
  <img src="/images/week6/task3A_1.png" alt="my alt text"/>
  <figcaption>Figure 21. Target variable's address </figcaption>
</figure>

The `printf()` function accepts one format specifier that can be used to modify the program's memory: the **`%n` specifier**. The purpose of this specifier is to store the number of characters printed by the `printf()` function until that point in a given address. 

Much like in the previous task, we can write the variable's address in the beginning of the input string and forward the pointer using `%x`. But, instead of using `%s` to print the content in the address, we use `%n` to store the number of characters printed.

```python
target_add = 0x080e5068

content[0:4] = (target_add).to_bytes(4,byteorder="little")

fmt = b"%.8x" * 63 + b"%n"
content[4:4+len(fmt)] = fmt
```

<figure align="center">
  <img src="/images/week6/task3A_2.png" alt="my alt text"/>
  <figcaption>Figure 22. Target variable before and after </figcaption>
</figure>

In this case, the `target` variable will now have the value `0x000001fc` (508 in decimal), which is exactly the number of characters expected, containing 4 characters for the address in the start of the string plus 63\*8 characters (8 characters for each address forwarded as we are using `%.8x`).


### Task 3.B

Following the previous step, we now want to write a specific value, `0x5000`, to the `target` variable.

To achieve this, use can use a specifier similar to the previously used `%.8x`. What this specifier does is to set the length of the content to be printed to 8 characters, inserting a padding of '0' characters to the left if the integer does not necessarily occupy all 8 characters (e.g. `0x00ffffff` would be displayed as `0xffffff`). Alternatively, `%8x` could also be used, but instead of padding with '0', it would insert empty space characters as padding.

In this case, we know that we need to print 4 initial characters (variable address in the format string) and 63\*8 characters for the `%x` memory content prints. For the `%n` specifier to write the value `0x5000` (20480), we need to print the rest of the characters using the previously mentioned specifier.

As the added specifier `newstr` will forward the pointer another 8 bytes, we must only use 62 `%x` before.

```python
target_add = 0x080e5068

content[0:4] = (target_add).to_bytes(4,byteorder="little")

desired_value = 0x5000

extra_chars = desired_value - (62 * 8) - 4

newstr = "%." + str(extra_chars) + "x"

fmt = (b"%.8x" * 62) + str.encode(newstr)  + b"%n"

content[4:4+len(fmt)] = fmt
```

Another possible script would be:

```python
target_add = 0x080e5068

content[0:4] = (target_add).to_bytes(4,byteorder="little")

fmt = s = "%.20476x%64$n" # 20476 = 20480 - 4 

content[4:4+len(fmt)] = fmt
```

<figure align="center">
  <img src="/images/week6/task3B_1.png" alt="my alt text"/>
  <figcaption>Figure 23. Target variable before </figcaption>
</figure>

<figure align="center">
  <img src="/images/week6/task3B_2.png" alt="my alt text"/>
  <figcaption>Figure 24. Target variable after </figcaption>
</figure>



