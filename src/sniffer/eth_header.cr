module Sniffer
  struct EtherHeader < Header
    getter :ether_dhost, :ether_shost, :ether_type

    @ether_dhost : EthMac
    @ether_shost : EthMac
    @ether_type : UInt16

    def initialize(io : IO)
      @ether_dhost = StaticArray(UInt8, 6).new(0_u8)
      @ether_shost = StaticArray(UInt8, 6).new(0_u8)

      6.times do |i|
        @ether_dhost[i] = read_u8(io)
      end

      6.times do |i|
        ether_shost[i] = read_u8(io)
      end

      @ether_type = read_u16(io)
    end

    def inspect
      puts "Destination Host: #{@ether_dhost.map { |uint16| "%02x" % uint16 }.join(":")}"
      puts "Source Host: #{@ether_shost.map { |uint16| "%02x" % uint16 }.join(":")}"
      puts "Ether Types: #{ETHER_NAMES[@ether_type]?}"
    end
  end
end
