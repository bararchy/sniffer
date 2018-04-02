module Sniffer
  struct EtherHeader
    getter :ether_dhost, :ether_shost, :ether_type

    @ether_dhost : EthMac
    @ether_shost : EthMac
    @ether_type : UInt16

    def initialize(bytes : Bytes)
      @ether_dhost = StaticArray(UInt8, 6).new(0_u8)
      bytes[0, 6].each_with_index do |b, i|
        @ether_dhost[i] = b
      end
      @ether_shost = StaticArray(UInt8, 6).new(0_u8)
      bytes[6, 6].each_with_index do |b, i|
        @ether_shost[i] = b
      end

      @ether_type = IO::ByteFormat::NetworkEndian.decode(UInt16, bytes[12, 2])
    end

    def inspect
      puts "Destination Host: #{@ether_dhost.map { |uint16| "%02x" % uint16 }.join(":")}"
      puts "Source Host: #{@ether_shost.map { |uint16| "%02x" % uint16 }.join(":")}"
      puts "Ether Types: #{ETHER_NAMES[@ether_type]?}"
    end
  end
end
