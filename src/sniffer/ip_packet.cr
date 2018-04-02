module Sniffer
  struct IPPacket
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

    def initialize(bytes : Bytes)
      @version = IO::ByteFormat::NetworkEndian.decode(UInt8, bytes[0, 1])
      @ihl = IO::ByteFormat::NetworkEndian.decode(UInt8, bytes[1, 1])
      @tos = IO::ByteFormat::NetworkEndian.decode(UInt8, bytes[2, 1])
      @tot_len = IO::ByteFormat::NetworkEndian.decode(UInt16, bytes[3, 2])
      @id = IO::ByteFormat::NetworkEndian.decode(UInt16, bytes[5, 2])
      @frag_off = IO::ByteFormat::NetworkEndian.decode(UInt16, bytes[7, 2])
      @ttl = IO::ByteFormat::NetworkEndian.decode(UInt8, bytes[9, 1])
      @protocol = IO::ByteFormat::NetworkEndian.decode(UInt8, bytes[10, 1])
      @check = IO::ByteFormat::NetworkEndian.decode(UInt16, bytes[11, 2])
      @saddr = IO::ByteFormat::NetworkEndian.decode(UInt32, bytes[13, 4])
      @daddr = IO::ByteFormat::NetworkEndian.decode(UInt32, bytes[17, 4])
    end

    def inspect
      puts "IP Version: #{(@version & 0xf0) >> 4}"
      puts "TTL: #{@ttl}"
      puts "Protocol: #{IP_PROTOCOL[@protocol.to_i32]?}"
      puts "Source Address: #{addr2string(@saddr)}"
      puts "Destination Address: #{addr2string(@daddr)}"
    end

    def addr2string(addr : UInt32)
      "#{(addr & 0xff000000) >> 24}.#{(addr & 0x00ff0000) >> 16}.#{(addr & 0x0000ff00) >> 8}.#{addr & 0x000000ff}"
    end
  end
end
