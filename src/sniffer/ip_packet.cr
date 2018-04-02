module Sniffer
  struct IPPacket < Header
    getter :tot_len, :protocol
    @version : UInt8
    @ihl : UInt8
    @tos : UInt8
    @tot_len : UInt16
    @id : UInt16
    @frag_off : UInt16
    @ttl : UInt8
    @protocol : UInt8
    @check : UInt16
    @saddr : UInt32
    @daddr : UInt32

    def initialize(io : IO)
      @version = read_u8(io)
      @ihl = read_u8(io)
      @tos = read_u8(io)
      @tot_len = read_u16(io)
      @id = read_u16(io)
      @frag_off = read_u16(io)
      @ttl = read_u8(io)
      @protocol = read_u8(io)
      @check = read_u16(io)
      @saddr = read_u32(io)
      @daddr = read_u32(io)
    end

    def inspect
      puts "IP Version: #{(@version & 0xf0) >> 4}"
      puts "TTL: #{@ttl}"
      puts "Protocol: #{IP_PROTOCOL[@protocol.to_i32]?}"
      puts "Source Address: #{addr2string(@saddr)}"
      puts "Destination Address: #{addr2string(@daddr)}"
    end

    def protocol_string : String
      IP_PROTOCOL[@protocol.to_i32]? || ""
    end

    def addr2string(addr : UInt32)
      "#{(addr & 0xff000000) >> 24}.#{(addr & 0x00ff0000) >> 16}.#{(addr & 0x0000ff00) >> 8}.#{addr & 0x000000ff}"
    end
  end
end
