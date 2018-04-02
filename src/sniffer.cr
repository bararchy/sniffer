require "socket"
require "./sniffer/**"

module Sniffer
  extend self

  def sniff
    # Raw socket
    s = Socket.new(Socket::Family.new(PACKET), Socket::Type::RAW, Socket::Protocol.new(ETH_P_ALL))
    loop do
      begin
        packet = Bytes.new(1024)
        bytes_read, client_addr = s.receive(packet)
        puts "READ: #{bytes_read}\nClient: #{client_addr}"
        puts packet[0, 14].to_unsafe.as(EtherHeader)
        EtherHeader.new(packet[0, 14]).inspect
        IPPacket.new(packet[14, sizeof(IPPacket)]).inspect
      rescue e : Exception
        puts "Error: #{e.inspect_with_backtrace}"
        next
      end
    end
    s.close
  end
end
