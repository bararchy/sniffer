module Sniffer
  abstract struct Header
    def read_u8(io)
      io.read_bytes(UInt8, IO::ByteFormat::NetworkEndian) || raise IO::EOFError.new
    end

    def read_u16(io)
      io.read_bytes(UInt16, IO::ByteFormat::NetworkEndian) || raise IO::EOFError.new
    end

    def read_u32(io)
      io.read_bytes(UInt32, IO::ByteFormat::NetworkEndian) || raise IO::EOFError.new
    end

    def read_u64(io)
      io.read_bytes(UInt64, IO::ByteFormat::NetworkEndian) || raise IO::EOFError.new
    end
  end
end
