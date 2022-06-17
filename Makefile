all:
	gcc fmem_fuse.c -o fmem_fuse `pkg-config fuse --cflags --libs`

clean:
	rm -f fmem_fuse
