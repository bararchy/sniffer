# sniffer

Sniffer is a project to try and decipher network packets from the ETH level and up.  
One of the goals of this project is not to relay on libpcap  

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  sniffer:
    github: bararchy/sniffer
```

## Usage

You have to run the code as root to allow raw sockets.  
```crystal
require "sniffer"

Sniffer.sniff
```


## Development

TODO: Write development instructions here

## Contributing

1. Fork it ( https://github.com/bararchy/sniffer/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [bararchy](https://github.com/bararchy) Bar Hofesh - creator, maintainer
