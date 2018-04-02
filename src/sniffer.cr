require "./sniffer/header"
require "socket"
require "./sniffer/**"

module Sniffer
  def self.sniff
    # Raw socket
    s = Socket.new(Socket::Family.new(PACKET), Socket::Type::RAW, Socket::Protocol.new(ETH_P_ALL))
    loop do
      begin
        puts "NEW PACKET"
        EtherHeader.new(s).inspect
        IPPacket.new(s).inspect
      rescue e : Exception
        puts "Error: #{e.inspect_with_backtrace}"
        next
      end
    end
    s.close
  end
end
