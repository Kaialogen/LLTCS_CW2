import subprocess

def run_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, _ = process.communicate()
    return stdout.decode()

# Commands for libc.so.6
libc_commands = [
    "nm -D libc.so.6 | grep ' puts'",
    "nm -D libc.so.6 | grep ' system'",
    "nm -D libc.so.6 | grep ' exit'",
    "strings -a -t x libc.so.6 | grep '/bin/sh'"
]

# Commands for itc_app
itc_app_commands = [
    "objdump -d itc_app | grep -A1 '<puts@plt>'",
    "objdump -t itc_app | grep ' main'",
    "nm itc_app | grep ' main'",
    "objdump -R itc_app | grep ' puts'"
]

print("=== libc.so.6 Offsets ===")
for cmd in libc_commands:
    print(f"Running command: {cmd}")
    output = run_command(cmd)
    print(output)

print("=== itc_app Addresses ===")
for cmd in itc_app_commands:
    print(f"Running command: {cmd}")
    output = run_command(cmd)
    print(output)
