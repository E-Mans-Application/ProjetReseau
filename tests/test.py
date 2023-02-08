import subprocess, platform

NUMBER = 20

args = lambda i: "%d [::1]:%d [::1]:%d -v=e" % (40000 + i, 40000 + (i + 1) % NUMBER,  40000 + (i + NUMBER - 1) % NUMBER)

if platform.system() == "Windows":
    cmd = lambda i: "start ../target/debug/projet.exe %s" % args(i)
else:
    cmd = lambda i: "gnome-terminal -- sh -c \"bash -c \\\"../target/debug/projet %s\\\"\"" % args(i)


for i in range(NUMBER):
    print(cmd(i))
    subprocess.call(cmd(i), shell=True)