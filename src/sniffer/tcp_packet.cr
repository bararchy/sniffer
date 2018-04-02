# typedef struct {
#   uint16_t src_port;
#   uint16_t dst_port;
#   uint32_t seq;
#   uint32_t ack;
#   uint8_t  data_offset;  // 4 bits
#   uint8_t  flags;
#   uint16_t window_size;
#   uint16_t checksum;
#   uint16_t urgent_p;
# } tcp_header_t;

module Sniffer
  struct TCPPacket < Header
    getter :src_port, :dst_port
    @src_port : UInt16
    @dst_port : UInt16
    @seq : UInt32
    @ack : UInt16
    @data_offset : UInt8
    @flags : UInt8
    @window_size : UInt16
    @checksum : UInt16
    @urgent_p : UInt16

    def initialize(io : IO)
      @src_port = read_u16(io)
      @dst_port = read_u16(io)
      @seq = read_u32(io)
      @ack = read_u16(io)
      @data_offset = read_u8(io)
      @flags = read_u8(io)
      @window_size = read_u16(io)
      @checksum = read_u16(io)
      @urgent_p = read_u16(io)
    end

    def inspect
      puts "TCP Packet"
      puts "Source port: #{@src_port}"
      puts "Destination port: #{@dst_port}"
    end
  end
end
