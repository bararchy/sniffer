# struct udphdr {
#          u_int16_t uh_sport;           /* source port */
#          u_int16_t uh_dport;           /* destination port */
#          u_int16_t uh_ulen;            /* udp length */
#          u_int16_t uh_sum;             /* udp checksum */
# };

module Sniffer
  struct UDPPacket < Header
    getter :src_port, :dst_port
    @src_port : UInt16
    @dst_port : UInt16
    @len : UInt16
    @sum : UInt16

    def initialize(io : IO)
      @src_port = read_u16(io)
      @dst_port = read_u16(io)
      @len = read_u16(io)
      @sum = read_u16(io)
    end

    def inspect
      puts "UDP Packet"
      puts "Source port: #{@src_port}"
      puts "Destination port: #{@dst_port}"
    end
  end
end
