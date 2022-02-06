ifeq ($(shell uname -s),Darwin)
SYSLIBS =
CC	= clang++ -std=c++11
else
SYSLIBS	= -Wl,-lrt,-lstdc++
CC	= g++ -std=gnu++11
endif
APPCC	= ${CC} -g -c
APPLNK	= ${CC}
LIBCC	= ${APPCC} -fPIC
LIBLNK	= ${CC} -shared

all: libjen jen jentest

clean:
	rm -f libjet.so jen jentest *.o test.*

install:
	cp libjen.so /usr/local/lib
	cp jen /usr/local/bin
	cp jentest /usr/local/bin

.PHONY:
	clean

LIBJENOBJS = aes.o api.o asn.o base64.o cipher.o compress.o crc32.o deflate.o des.o digest.o file.o hmac.o inflate.o log.o md5.o num.o passphrase.o pbc2.o prng.o random.o rsa.o sha.o socket.o uri.o x509.o
JENOBJS = app.o buffer.o channel.o ${OBJS}
JENTESTOBJS = jentest.o ${OBJS}

libjen: ${LIBJENOBJS}
	${LIBLNK} ${LIBJENOBJS} ${SYSLIBS} -o $@.so

jen: ${JENOBJS}
	${APPLNK} ${JENOBJS} ${SYSLIBS} -o $@

jentest: ${JENTESTOBJS}
	${APPLNK} ${JENTESTOBJS} ${SYSLIBS} -o $@

aes.o: aes.cpp
	${LIBCC} aes.cpp

api.o: api.cpp
	${LIBCC} api.cpp

app.o: app.cpp
	${APPCC} app.cpp

asn.o: asn.cpp
	${LIBCC} asn.cpp

base64.o: base64.cpp
	${LIBCC} base64.cpp

buffer.o: buffer.cpp
	${APPCC} buffer.cpp

channel.o: channel.cpp
	${APPCC} channel.cpp

cipher.o: cipher.cpp
	${LIBCC} cipher.cpp

compress.o: compress.cpp
	${LIBCC} compress.cpp

crc32.o: crc32.cpp
	${LIBCC} crc32.cpp

deflate.o: deflate.cpp
	${LIBCC} -Wno-deprecated-register deflate.cpp

des.o: des.cpp
	${LIBCC} des.cpp

digest.o: digest.cpp
	${LIBCC} digest.cpp

file.o: file.cpp
	${LIBCC} file.cpp

hmac.o: hmac.cpp
	${LIBCC} hmac.cpp

inflate.o: inflate.cpp
	${LIBCC} -Wno-deprecated-register inflate.cpp

jentest.o: jentest.cpp
	${APPCC} jentest.cpp

log.o: log.cpp
	${LIBCC} log.cpp

md5.o: md5.cpp
	${LIBCC} md5.cpp

num.o: num.cpp
	${LIBCC} num.cpp

passphrase.o: passphrase.cpp
	${LIBCC} passphrase.cpp

pbc2.o: pbc2.cpp
	${LIBCC} pbc2.cpp

prng.o: prng.cpp
	${LIBCC} prng.cpp

random.o: random.cpp	
	${LIBCC} random.cpp

rsa.o: rsa.cpp
	${LIBCC} rsa.cpp

sha.o: sha.cpp
	${LIBCC} sha.cpp

socket.o: socket.cpp
	${LIBCC} socket.cpp

uri.o: uri.cpp
	${LIBCC} uri.cpp

x509.o: x509.cpp
	${LIBCC} x509.cpp

aes.cpp: aes.h asn.h oid.h
	touch aes.cpp

api.cpp: api.h
	touch api.cpp

app.cpp: api.h app.h file.h log.h passphrase.h socket.h uri.h
	touch app.cpp

asn.cpp: asn.h
	touch asn.cpp

base64.cpp: base64.h
	touch base64.cpp

buffer.cpp: buffer.h
	touch buffer.cpp

channel.cpp: channel.h log.h
	touch channel.cpp

cipher.cpp: cipher.h random.h
	touch cipher.cpp

compress.cpp: compress.h
	touch compress.cpp

crc32.cpp: crc32.h
	touch crc32.cpp

deflate.cpp: deflate.h
	touch deflate.cpp

des.cpp: des.h asn.h oid.h
	touch des.cpp

digest.cpp: digest.h
	touch digest.cpp

file.cpp: file.h log.h
	touch file.cpp

hmac.cpp: hmac.h md5.h sha.h
	touch hmac.cpp

inflate.cpp: inflate.h
	touch inflate.cpp

jentest.cpp: jentest.h base64.h compress.h file.h hmac.h num.h md5.h passphrase.h pbc2.h prng.h random.h rsa.h sha.h x509.h
	touch jentest.cpp

log.cpp: log.h
	touch log.cpp

md5.cpp: md5.h asn.h oid.h
	touch md5.cpp

num.cpp: num.h asn.h
	touch num.cpp

passphrase.cpp: passphrase.h base64.h num.h random.h
	touch passphrase.cpp

pbc2.cpp: pbc2.h
	touch pbc2.cpp

prng.cpp: prng.h
	touch prng.cpp

random.cpp: random.h
	touch random.cpp

rsa.cpp: rsa.h asn.h base64.h oid.h pbc2.h
	touch rsa.cpp

sha.cpp: sha.h asn.h oid.h
	touch sha.cpp

socket.cpp: socket.h log.h
	touch socket.cpp

uri.cpp: uri.h
	touch uri.cpp

x509.cpp: x509.h asn.h base64.h oid.h sha.h
	touch x509.cpp

aes.h: api.h cipher.h
	touch aes.h

app.h: api.h channel.h file.h random.h socket.h uri.h x509.h
	touch app.h

asn.h: api.h
	touch asn.h

base64.h: api.h
	touch base64.h

buffer.h: api.h
	touch buffer.h

channel.h: api.h buffer.h des.h hmac.h random.h rsa.h sha.h socket.h uri.h
	touch channel.h

cipher.h: api.h
	touch cipher.h

compress.h: api.h
	touch compress.h

crc32.h: compress.h
	touch crc32.h

deflate.h: compress.h
	touch deflate.h

des.h: api.h cipher.h
	touch des.h

digest.h: api.h
	touch digest.h

file.h: api.h
	touch file.h

hmac.h: api.h sha.h
	touch hmac.h

inflate.h: compress.h
	touch inflate.h

jentest.h: aes.h api.h des.h
	touch jentest.h

log.h: api.h
	touch log.h

md5.h: api.h digest.h
	touch md5.h

num.h: api.h random.h
	touch num.h

passphrase.h: api.h
	touch passphrase.h

pbc2.h: api.h hmac.h prng.h
	touch pbc2.h

prng.h: api.h des.h random.h
	touch prng.h

random.h: api.h
	touch random.h

rsa.h: api.h num.h random.h
	touch rsa.h

sha.h: api.h digest.h
	touch sha.h

socket.h: api.h
	touch socket.h

uri.h: api.h
	touch uri.h

x509.h: api.h rsa.h
	touch x509.h
