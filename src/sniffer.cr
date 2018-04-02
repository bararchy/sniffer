require "./sniffer/header"
require "socket"
require "io/hexdump"
require "./sniffer/**"

module Sniffer
  def self.sniff
    # Raw socket
    s = Socket.new(Socket::Family.new(PACKET), Socket::Type::RAW, Socket::Protocol.new(ETH_P_ALL))
    loop do
      begin
        puts "NEW PACKET"
        eth = EtherHeader.new(s)
        ip = IPPacket.new(s)

        case ip.protocol_string.downcase
        when "tcp"
          proto_packet = TCPPacket.new(s)
          p_size = sizeof(TCPPacket)
        when "udp"
          proto_packet = UDPPacket.new(s)
          p_size = sizeof(UDPPacket)
        else
          p_size = 0
        end

        data = Bytes.new(ip.tot_len - sizeof(IPPacket) - p_size)
        read, client = s.receive(data)

        eth.inspect
        ip.inspect
        proto_packet.inspect if proto_packet

        puts String.new(data)
      rescue e : Exception
        puts "Error: #{e.inspect_with_backtrace}"
        next
      end
    end
    s.close
  end
end
