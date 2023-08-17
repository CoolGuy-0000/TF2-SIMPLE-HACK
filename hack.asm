FORMAT PE GUI 4.0

InjectCodeSize = 1000h

section '.text' code readable executable

__entry:


enter 4,0
push 0
push 80h
push 3
push 0
push 0
push 80000000h
push str_hl2exe
call [KERNEL32.CreateFileA]
cmp eax, 0FFFFFFFFh
je .invalid_file
mov edi, eax

push 0
push edi
call [KERNEL32.GetFileSize]
mov ebx, eax
push 4 ;PAGE_READWRITE
push 1000h or 2000h ;MEM_COMMIT | MEM_RESERVE
push ebx
push 0
call [KERNEL32.VirtualAlloc]
mov esi, eax

push 0
push 0
push ebx ;size
push esi ;buffer
push edi ;handle
call [KERNEL32.ReadFile]

push edi ;handle
call [KERNEL32.CloseHandle]


mov eax, [esi+60] ;e_lfanew
lea eax, [esi+eax] ;NT Header
mov edx, [eax+44] ;BaseOfCode
mov DWORD PTR eax+100, 3000h ;SizeOfStackCommit
mov DWORD PTR eax+160, 0 ;reloc VA
mov DWORD PTR eax+164, 0 ;reloc VirtualSize
mov [ebp-4], eax
mov cx, [eax+6] ;NumberOfSections
lea eax, [eax+248] ;first section



.L1:

cmp cx, 0
je .L1_Continue
cmp DWORD PTR eax+12, edx
jne .L1_Continue2

mov edi, [ebp-4]
mov edx, [edi+40]
sub edx, [edi+44]
add edx, [eax+20]

add edx, esi

push esi
push ecx

cld
mov ecx, ndata_size 
mov esi, ndata
mov edi, edx
rep movsb

pop ecx
pop esi

mov edx, 0FFFFFFFFh

.L1_Continue2:
or DWORD PTR eax+36, 0E0000000h ;executable | readable | writeable
add eax, 40
dec cx
jmp .L1
.L1_Continue:

push 0
push 80h
push 2
push 0
push 0
push 40000000h
push str_hl2exe
call [KERNEL32.CreateFileA]
mov edi, eax
push 0
push 0
push ebx
push esi
push edi
call [KERNEL32.WriteFile]

push edi
call [KERNEL32.CloseHandle]

push 0
push 80h
push 2
push 0
push 0
push 40000000h
push __str_hl2injectbin
call [KERNEL32.CreateFileA]
mov edi, eax

push 0
push 0
push OriginalInjectCode_RawDataSize
push OriginalInjectCode
push edi
call [KERNEL32.WriteFile]

push edi
call [KERNEL32.CloseHandle]

.invalid_file:
leave
ret

section '.data' data readable writeable 

ijdata:

OriginalInjectCode:
call ijdata.GetCurrentAddress
mov ebp, eax
mov ebx, [esp+4];KERNEL32 ImageBase

xor ecx, ecx
lea edx, [ebp+ijdata_init_funclist]

.LoadFunctions:
lea esi, [edx+ecx*4]
mov edi, [edx+ecx*4]
test edi, edi 
jz .AllFunctionLoaded
add edi, ebp
push edi
push ebx
call ijdata.GetProcAddress
mov [esi], eax
inc ecx
jmp .LoadFunctions

.AllFunctionLoaded:
.get_engine_dll:

push 1000 ;1000 ms
call DWORD PTR ebp+ijdata.Sleep

lea eax, [ebp+ijdata.str_enginedll]
push eax
call DWORD PTR ebp+ijdata.GetModuleHandleA
test eax, eax
jz .get_engine_dll

mov edi, eax
mov [esp], edi

lea esi,[ebp+ijdata.mask_clientside_svcheats]
push esi
lea esi,[ebp+ijdata.aob_clientside_svcheats]
push esi 
push edi
call ijdata.GetAddrByAOB
test eax, eax
jz .think

mov edi, eax

lea esi, [esp+4]
push esi
push 40h
push ijdata.ijcodelen_clientside_svcheats
push edi
call DWORD PTR ebp+ijdata.VirtualProtect

push esi
push edi

cld
mov ecx, ijdata.ijcodelen_clientside_svcheats
lea esi, [ebp+ijdata.ijcode_clientside_svcheats]
rep movsb

pop edi
pop esi

push esi
mov esi, [esi]
push esi
push ijdata.ijcodelen_clientside_svcheats
push edi
call DWORD PTR ebp+ijdata.VirtualProtect

.think:
jmp .think

xor eax, eax
ret 4

;arg1 - module, arg2 - function name
ijdata.GetProcAddress:
enter 4, 0
pushad

mov ecx, [ebp+8];module
mov edi, [ecx+60] ;PE Header
add edi, ecx
mov ebx, [edi+120];export table virtual address
add ebx, ecx
mov [ebp-4], ebx ;export table structure

xor eax, eax
mov ebx, [ebx+32] ;Name Table rva
add ebx, ecx

.L1:
mov esi, [ebx+eax*4];source
test esi, esi
jz .NotFounded

add esi, ecx
push esi
push DWORD PTR ebp+12
call ijdata.StrEqual
jz .founded
inc eax
jmp .L1
.founded:
mov ebx, [ebp-4]
mov edi, [ebx+36]
add edi, ecx
movzx eax, WORD PTR edi+eax*2
mov edi, [ebx+28]
add edi, ecx
mov eax, [edi+eax*4]
add eax, ecx
mov [ebp-4], eax
jmp .return
.NotFounded:
mov DWORD PTR ebp-4, 0
.return:
popad
mov eax, [ebp-4]
leave
ret 8

ijdata.GetCurrentAddress:
mov eax, [esp]
sub eax, 5
ret


;arg1 - str1, target
;arg2 - str2, source
ijdata.StrEqual:
enter 0,0
pushad

xor eax, eax
xor edi, edi
mov ecx, [ebp+8]
mov esi, [ebp+12]

.L1:
mov dl, [ecx+edi]
test dl, dl
jz .IsEqual
mov bl, [esi+edi]
test bl, bl
jz .NotEqual

sub dl, bl
test dl, dl
jnz .NotEqual

inc edi
jmp .L1

.NotEqual:
or al, 1
jmp .return
.IsEqual:
test al, 0
.return:
popad
leave
ret 8

;arg1 - module
;arg2 - aob
;arg3 - mask
ijdata.GetAddrByAOB:
enter 4,0
pushad

xor edx, edx ;correct count
xor esi, esi ;count
mov ecx, [ebp+8] ;module
mov edi, [ecx+60] ;PE HEADER
mov edi, [edi+ecx+80] ;SizeOfImage
mov eax, [ebp+12] ;aob
mov ebx, [ebp+16] ;mask

.L1:
cmp BYTE PTR ebx+edx, 0
je .calc_done
cmp BYTE PTR ebx+edx, 'x'
je .skip_byte
push edx
mov dl, BYTE PTR eax+edx
cmp BYTE PTR ecx+esi, dl
pop edx
je .correct_byte
xor edx, edx
inc esi
cmp esi, edi
je .reached_top
jmp .L1
.correct_byte:
inc edx
inc esi
cmp esi, edi
je .reached_top
jmp .L1
.skip_byte:
inc esi
cmp esi, edi
je .reached_top
jmp .L1

.reached_top:
mov DWORD PTR ebp-4, 0
jmp .return
.calc_done:
sub esi, edx
add ecx, esi
mov [ebp-4], ecx
.return:
popad
mov eax, [ebp-4]
leave
ret 12


ijdata_init_funclist = $-ijdata

ijdata.VirtualProtect = $-ijdata 
DD ijdata.str_VirtualProtect
ijdata.GetModuleHandleA = $-ijdata 
DD ijdata.str_GetModuleHandleA
ijdata.Sleep = $-ijdata
DD ijdata.str_Sleep
ijdata.NullFunc = $-ijdata 
DD 0



ijdata.str_VirtualProtect = $-ijdata
DB 'VirtualProtect',0
ijdata.str_GetModuleHandleA = $-ijdata
DB 'GetModuleHandleA',0
ijdata.str_Sleep = $-ijdata
DB 'Sleep',0


ijdata.str_enginedll = $-ijdata
DB 'engine.dll',0

ijdata.aob_clientside_svcheats = $-ijdata
DB 83h, 78h, 30h, 00h, 75h, 44h, 80h, 3Dh
ijdata.mask_clientside_svcheats = $-ijdata
DB '........',0
ijdata.ijcode_clientside_svcheats = $-ijdata
DB 0C7h, 40h, 30h, 01h, 00h, 00h, 00h
DB 0EBh, 41h
ijdata.ijcodelen_clientside_svcheats = ($-ijdata) - ijdata.ijcode_clientside_svcheats 

OriginalInjectCode_RawDataSize = $-OriginalInjectCode
OriginalInjectCode_VirtualSize = 1000h

str_hl2exe DB 'hl2.exe',0
__str_hl2injectbin DB 'hl2.inject.bin',0

section '.idata' data import readable writeable 

DD 0,0,0,RVA str_KERNEL32DLL,RVA KERNEL32.IAT
DD 0,0,0,0,0

KERNEL32.IAT:
	KERNEL32.CreateFileA DD RVA KERNEL32.IAT.CreateFileA
	KERNEL32.CloseHandle DD RVA KERNEL32.IAT.CloseHandle
	KERNEL32.WriteFile DD RVA KERNEL32.IAT.WriteFile
	KERNEL32.ReadFile DD RVA KERNEL32.IAT.ReadFile
	KERNEL32.GetFileSize DD RVA KERNEL32.IAT.GetFileSize
	KERNEL32.VirtualAlloc DD RVA KERNEL32.IAT.VirtualAlloc
	KERNEL32.SetFilePointer DD RVA KERNEL32.IAT.SetFilePointer
	KERNEL32.GetModuleHandleA DD RVA KERNEL32.IAT.GetModuleHandleA
	DD 0
	
KERNEL32.IAT.CreateFileA:
		DW 0
		DB 'CreateFileA',0
KERNEL32.IAT.CloseHandle:
		DW 0
		DB 'CloseHandle',0
KERNEL32.IAT.WriteFile:
		DW 0
		DB 'WriteFile',0
KERNEL32.IAT.ReadFile:
		DW 0
		DB 'ReadFile',0
KERNEL32.IAT.GetFileSize:
		DW 0
		DB 'GetFileSize',0
KERNEL32.IAT.VirtualAlloc:
		DW 0
		DB 'VirtualAlloc',0
KERNEL32.IAT.SetFilePointer:
		DW 0
		DB 'SetFilePointer',0
KERNEL32.IAT.GetModuleHandleA:
		DW 0
		DB 'GetModuleHandleA',0
		
str_KERNEL32DLL DB 'KERNEL32.DLL',0

section '.ndata' readable writeable

ndata:
call ndata.GetCurrentAddress
mov ebp, eax
mov ebx, [fs:30h]
mov ebx, [ebx+0Ch]
mov ebx, [ebx+14h]
mov ebx, [ebx]
mov ebx, [ebx]
mov ebx, [ebx+10h];KERNEL32 ImageBase

xor ecx, ecx
lea edx, [ebp+ndata_init_funclist]

.LoadFunctions:
lea esi, [edx+ecx*4]
mov edi, [edx+ecx*4]
test edi, edi 
jz .AllFunctionLoaded
add edi, ebp
push edi
push ebx
call ndata.GetProcAddress
mov [esi], eax
inc ecx
jmp .LoadFunctions

.AllFunctionLoaded:

push 40h ;PAGE_EXECUTE_READWRITE
push 1000h or 2000h
push OriginalInjectCode_VirtualSize
push 0
call DWORD PTR ebp+ndata.VirtualAlloc
mov edi, eax

push 0
push 80h
push 3
push 0
push 0
push 80000000h
lea eax, [ebp+ndata.str_hl2Injectbin]
push eax
call DWORD PTR ebp+ndata.CreateFileA
mov esi, eax

push 0
push 0
push OriginalInjectCode_RawDataSize
push edi
push esi
call DWORD PTR ebp+ndata.ReadFile

push esi
call DWORD PTR ebp+ndata.CloseHandle

push 0
push 0
push ebx
push edi
push 1000h ;stack size
push 0
call DWORD PTR ebp+ndata.CreateThread

push 40h ;PAGE_EXECUTE_READWRITE
push 1000h or 2000h
push 2000h
push 0
call DWORD PTR ebp+ndata.VirtualAlloc
mov edi, eax

push 2000h
push edi
lea eax, [ebp+ndata.str_PATH]
push eax
call DWORD PTR ebp+ndata.GetEnvironmentVariable 
mov esi, eax

lea eax, [edi+esi]
push eax
push 2000h
call DWORD PTR ebp+ndata.GetCurrentDirectory
add esi, eax

push edi

cld
mov ecx, ndata.strlen_bin
lea edi, [edi+esi]
lea esi, [ebp+ndata.str_bin]
rep movsb

pop edi

push edi
lea eax, [ebp+ndata.str_PATH]
push eax
call DWORD PTR ebp+ndata.SetEnvironmentVariable

push 0
push 0
lea eax, [ebp+ndata.str_launcherdll]
push eax
call DWORD PTR ebp+ndata.LoadLibraryExA

lea ecx, [ebp+ndata.str_LauncherMain]
push ecx
push eax
call ndata.GetProcAddress
mov edi, eax

push 1 ;nCmdShow

call DWORD PTR ebp+ndata.GetCommandLineA
push eax ;lpCmdLine

push 0 ;hPrevInstance

push 0
call DWORD PTR ebp+ndata.GetModuleHandleA
push eax ;hInstance

call edi ;LauncherMain

ret

;-------------------------------------

;arg1 - module, arg2 - function name
ndata.GetProcAddress:
enter 4, 0
pushad

mov ecx, [ebp+8];module
mov edi, [ecx+60] ;PE Header
add edi, ecx
mov ebx, [edi+120];export table virtual address
add ebx, ecx
mov [ebp-4], ebx ;export table structure

xor eax, eax
mov ebx, [ebx+32] ;Name Table rva
add ebx, ecx

.L1:
mov esi, [ebx+eax*4];source
test esi, esi
jz .NotFounded

add esi, ecx
push esi
push DWORD PTR ebp+12
call ndata.StrEqual
jz .founded
inc eax
jmp .L1
.founded:
mov ebx, [ebp-4]
mov edi, [ebx+36]
add edi, ecx
movzx eax, WORD PTR edi+eax*2
mov edi, [ebx+28]
add edi, ecx
mov eax, [edi+eax*4]
add eax, ecx
mov [ebp-4], eax
jmp .return
.NotFounded:
mov DWORD PTR ebp-4, 0
.return:
popad
mov eax, [ebp-4]
leave
ret 8

ndata.GetCurrentAddress:
mov eax, [esp]
sub eax, 5
ret


;arg1 - str1, target
;arg2 - str2, source
ndata.StrEqual:
enter 0,0
pushad

xor eax, eax
xor edi, edi
mov ecx, [ebp+8]
mov esi, [ebp+12]

.L1:
mov dl, [ecx+edi]
test dl, dl
jz .IsEqual
mov bl, [esi+edi]
test bl, bl
jz .NotEqual

sub dl, bl
test dl, dl
jnz .NotEqual

inc edi
jmp .L1

.NotEqual:
or al, 1
jmp .return
.IsEqual:
test al, 0
.return:
popad
leave
ret 8


ndata_init_funclist = $-ndata

ndata.CreateThread = $-ndata 
DD ndata.str_CreateThread
ndata.VirtualAlloc = $-ndata 
DD ndata.str_VirtualAlloc
ndata.CreateFileA = $-ndata 
DD ndata.str_CreateFileA
ndata.ReadFile = $-ndata 
DD ndata.str_ReadFile
ndata.CloseHandle = $-ndata 
DD ndata.str_CloseHandle
ndata.GetModuleHandleA = $-ndata 
DD ndata.str_GetModuleHandleA
ndata.GetCurrentDirectory = $-ndata 
DD ndata.str_GetCurrentDirectory
ndata.GetEnvironmentVariable = $-ndata 
DD ndata.str_GetEnvironmentVariable
ndata.SetEnvironmentVariable = $-ndata 
DD ndata.str_SetEnvironmentVariable
ndata.GetCommandLineA = $-ndata 
DD ndata.str_GetCommandLineA
ndata.LoadLibraryExA = $-ndata 
DD ndata.str_LoadLibraryExA

ndata.NullFunc = $-ndata 
DD 0

ndata.str_CreateThread = $-ndata
DB 'CreateThread',0

ndata.str_VirtualAlloc = $-ndata
DB 'VirtualAlloc',0

ndata.str_CreateFileA = $-ndata
DB 'CreateFileA',0

ndata.str_ReadFile = $-ndata
DB 'ReadFile',0

ndata.str_CloseHandle = $-ndata
DB 'CloseHandle',0

ndata.str_GetModuleHandleA = $-ndata
DB 'GetModuleHandleA',0

ndata.str_GetCurrentDirectory = $-ndata
DB 'GetCurrentDirectory',0

ndata.str_GetEnvironmentVariable = $-ndata
DB 'GetEnvironmentVariable',0

ndata.str_SetEnvironmentVariable = $-ndata
DB 'SetEnvironmentVariable',0

ndata.str_GetCommandLineA = $-ndata
DB 'GetCommandLineA',0

ndata.str_LoadLibraryExA = $-ndata 
DB 'LoadLibraryExA',0


ndata.str_PATH = $-ndata
DB 'PATH', 0

ndata.str_LauncherMain = $-ndata
DB 'LauncherMain',0

ndata.str_bin = $-ndata
DB '\bin;', 0
ndata.strlen_bin = ($-ndata) - ndata.str_bin
 
ndata.str_launcherdll = $-ndata
DB 'bin\launcher.dll', 0

ndata.str_hl2backupbin = $-ndata
DB 'hl2.backup.bin',0

ndata.str_hl2Injectbin = $-ndata
DB 'hl2.inject.bin',0


ndata_size = $-ndata