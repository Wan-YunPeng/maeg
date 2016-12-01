import tempfile
import subprocess

lname = './log'
args = ['qemu-x86_64']
args += ["-d", "exec", "-D", lname, './test']
devnull = open('/dev/null', 'wb')
input = 'aaaaaaaaaaaaaaaaaaaaaddddddddddddddddddddddddfffffffffffffffffffffffffffffff'
p = subprocess.Popen(args,stdin=subprocess.PIPE,stdout=devnull,stderr=devnull)
_, _ = p.communicate(input)
ret = p.wait()
print ret
devnull.close