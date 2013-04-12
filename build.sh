rm ./.otp.o ./ipaotp-plugin.so &> /dev/null
gcc -g -I/usr/include/nspr4 -c -fPIC otp.c -o otp.o
gcc -shared -Wl,-soname,libipaotp-plugin.so.1 -o libipaotp-plugin.so  otp.o
