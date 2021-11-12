# Work performed - Week #4

# CTF

The week #4 CTF challenge was based on an E-commerce WordPress website that was vulnerable by nature. The vulnerabilities encountered were related to the WordPress Plugins used in it. 

- We started by inspecting the source code (CTRL+U) of the available pages, searching for any relevant information.
- We found out the wordPress version, 5.8.1, which is a relatively recent version.
- Additionally, we also found out the website was using three WordPress plugins, WooCommerce 5.7.1, WooCommerce Booster 5.4.3, and Storefront.

<figure align="center">
  <img src="images/week4/pluginVersions.png" alt="my alt text"/>
  <figcaption>Figure 1. WordPress Plugins and corresponding versions</figcaption>
</figure>

- Also we found that the possible users were `admin` and `Orval Sanford`.
- Knowing that, we started to search for CVEs related to these versions of the plugins, getting to the [CVE-2021-34646](https://www.cvedetails.com/cve/CVE-2021-34646), which has an [exploit](https://www.exploit-db.com/exploits/50299) that we searched for in the Exploit Database and that was related to the exact same version we had of the WooCommerce Booster.
- Having downloaded the Python script for the exploit, we executed it using the URL to the page and a user ID (ID=1 for the `admin` account as shown [here](http://ctf-fsi.fe.up.pt:5001/wp-json/wp/v2/users/)).

<figure align="center">
  <img src="images/week4/exploit.png" alt="my alt text"/>
  <figcaption>Figure 2. Exploit execution</figcaption>
</figure>

After selecting one of the provided links, we got admin access to the website and then we only had to access the [edit.php](http://ctf-fsi.fe.up.pt:5001/wp-admin/edit.php) and click the first post available which contained the flag!

# SEED Lab Tasks

This week's suggested lab was [Environment Variable and Set-UID Lab](https://seedsecuritylabs.org/Labs_20.04/Software/Environment_Variable_and_SetUID/), from SEED labs, with the intent of providing us a better understanding of environment variables, `Set-UID` programs, and how these can be used for potential attacks.

## Task 1

As suggested, we explored the environment variables commands in the Linux shell, including `printenv`, `env`, `export`, and `unset` to display all the environment variables and add/remove some.

<figure align="center">
  <img src="images/week4/printenv.png" alt="Task1.1"/>
  <figcaption>Figure 3. `printenv` command (`env` has the same output)</figcaption>
</figure>

<figure align="center">
  <img src="images/week4/exportUnset.png" alt="Task1.2"/>
  <figcaption>Figure 4. `export` and `unset` commands</figcaption>
</figure>

## Task 2

### Step 1

After compiling and running the `myprintenv.c` file, saving the output to a file, we checked its contents to find the list of environment variables.

<figure align="center">
  <img src="images/week4/childEnvVars.png" alt="Task2.1"/>
  <figcaption>Figure 5. Child process Environment variables</figcaption>
</figure>

### Step 2 and 3

We saved the output of the program after commenting on the proposed line and, after comparing the two using the `diff` command, we concluded there were no differences between the outputs. 

<figure align="center">
  <img src="images/week4/diffEnvVars.png" alt="Task2.2"/>
  <figcaption>Figure 6. Zero differences between the Environment variables of both processes</figcaption>
</figure>

This means that both processes (parent and child) share the same environment variables, this is, when the parent used `fork()` to create the child process, it creates its own exact duplicate and one of the things that the child process inherits is the environment variables.

## Task 3

### Step 1

When first running the program, it provided no visible output.

<figure align="center">
  <img src="images/week4/myEnv.png" alt="Task3.1"/>
  <figcaption>Figure 7. Running `myenv.c` with NULL as the third argument of `execve()`</figcaption>
</figure>

### Step 2

After changing the `execve()` call to use the external variable `environ` as the third argument, the program displayed the environment variable list as output.

<figure align="center">
  <img src="images/week4/execve.png" alt="Task3.2"/>
  <figcaption>Figure 8. `execve()` with environ as third argument</figcaption>
</figure>

### Step 3

We could conclude, based on the previous steps, that when `execve()` function is called, the current process' environment variables **need to be used as the third parameter so the new program can inherit them**. By providing a NULL third parameter in Step 1, the new program created by `execve()` cannot inherit the environment variables and so, the `env` command provides empty output.

## Task 4

To verify that if by calling `system()` the environment variables of the calling process are passed, we ran the following program and checked the output. If you look at the implementation of the function, you will see that it uses `execl()` to execute `/bin/sh`; `execl()` calls `execve()`, passing to it the environment variables.

<figure align="center">
  <img src="images/week4/system.png" alt="Task4.1"/>
  <figcaption>Figure 9. `system()` execution</figcaption>
</figure>

We then verified that the program's output was a list of environment variables resulting from the `/usr/bin/env` execution.

## Task 5

### Step 1

First, we created a file named `task5.c` with the following C code:

<figure align="center">
  <img src="images/week4/task5.png" alt="Task5.1"/>
  <figcaption>Figure 10. Task 5 code</figcaption>
</figure>

## Step 2

Then, after compiling it, we changed its ownership to `root`, and made it a `Set-UID` program.

<figure align="center">
  <img src="images/week4/changePermissions.png" alt="Task5.1"/>
  <figcaption>Figure 11. Changing the executable file permissions and ownership</figcaption>
</figure>

### Step 3

After setting the `$LD_LIBRARY_PATH` and `$ANY_NAME` environment variables to a random value, we executed the program.

<figure align="center">
  <img src="images/week4/exportVars.png" alt="Task5.2"/>
  <figcaption>Figure 12. Exporting new Environment variables</figcaption>
</figure>

Looking at the output of the program, we realized that only the `$ANY_NAME` was available to the program.

<figure align="center">
  <img src="images/week4/newEnvVars.png" alt="Task5.3"/>
  <figcaption>Figure 13. Printing the Environment variables</figcaption>
</figure>


Only the `$ANY_NAME` variable appears because the `$LD_LIBRARY_PATH` is considered insecure as it might allow unauthorized programs access to system/malicious libraries, for example.

The command `sudo chmod 4755` uses the first number (4) to Set UID which means you'll run the file as the owner (in this case, `root`) regardless of which user is running it. That's a `Set-UID` process.

With all this, the superuser has an enabled by default protection system that results in `Set-UID` programs to ignore certain environment variables that are blacklisted. `$LD_LIBRARY_PATH` is one of them as we saw.

This way, the `$LD_LIBRARY_PATH` environment variable is not passed from the parent process to the `Set-UID` child process for the reasons mentioned above. All the others are because they don't get filtered by the security mechanism.

## Task 6 

The first thing to do in this task is to change the `$PATH` environment variable associated with the shell process. For that, we used this command: 

`export PATH=$(pwd):$PATH`

<figure align="center">
  <img src="images/week4/exportPath.png" alt="Task6.1"/>
  <figcaption>Figure 14. Changing the `$PATH` Environment variable</figcaption>
</figure>

Then, we created a file called "ls" that would contain our malicious code and gave it execute permissions with the following command:

`chmod u+x ls`

<figure align="center">
  <img src="images/week4/ls.png" alt="Task6.2"/>
  <figcaption>Figure 15. Malicious code file</figcaption>
</figure>

What happens is that when we run our `Set-UID` program and the `system("ls");` line is executed, the result is very similar to the previous task. Again, what happens is that when we run the executable, the shell forks a child process and passes the shell's environment variables to it, which includes our changed `$PATH`. As it's a `Set-UID` program and the owner of the executable file is `root`, the program itself will execute as `root` which means it will have high privileges. But this time, the previously mentioned protection in Task 5 won't work, because we are just editing the `$PATH` environment variable and not adding another blacklisted environment variable as in the case of `$LD_LIBRARY_PATH`. So the environment variables are the same in the `root` user as in the low-privilege user. However, when we execute the `system()` function the `/bin/sh` program is executed first and has a countermeasure that prevents itself from being executed in a `Set-UID` process. Basically, if `sh` detects that it is executed in a `Set-UID` process, it immediately changes the effective user ID to the process's real user ID, essentially dropping the privilege. When we execute `system("ls");` it will run our malicious code because it searches through the folders listed in the `$PATH` until it finds a file named “ls”, but as the user who initially run the executable, not as `root`.

<figure align="center">
  <img src="images/week4/whoamiUnprivileged.png" alt="Task6.3"/>
  <figcaption>Figure 16. Result of `system("whoami")` execution is the unprivileged user name</figcaption>
</figure>

<figure align="center">
  <img src="images/week4/lsHacked.png" alt="Task6.4"/>
  <figcaption>Figure 17. Result of `system("ls")` execution</figcaption>
</figure>

Since our victim program is a `Set-UID` program, the countermeasure in `/bin/dash` can prevent our attack. To see how our attack works without such a countermeasure, we need to link `/bin/sh` to another shell that does not have such a countermeasure, for example `zsh`. We use the following command to link `/bin/sh` to `/bin/zsh`:

`sudo ln -sf /bin/zsh /bin/sh`

The dropping privilege phase won't happen now and our program will run with the same permissions as the owner of the file, in this case, `root`, allowing us to do anything we want with the system.

<figure align="center">
  <img src="images/week4/whoamiPrivileged.png" alt="Task6.5"/>
  <figcaption>Figure 18. Result of `system("whoami")` execution after canceling dropping privilege</figcaption>
</figure>
