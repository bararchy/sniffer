# sniffer

Sniffer is a project to try and decipher network packets from the ETH level and up.  
One of the goals of this project is not to relay on libpcap  

## Installation
1. [Install Crystal](https://crystal-lang.org/docs/installation/)  

Add this to your application's `shard.yml`:

```yaml
dependencies:
  sniffer:
    github: bararchy/sniffer
```

## Usage

You have to run the code as root to allow raw sockets.  

In the root dir run `sudo crystal spec`  

or 

```crystal
require "sniffer"

Sniffer.sniff
```


## Development

* [x] ETH Header parse  
* [ ] IP Header parse  
* [ ] TCP Header parse  
* [ ] UDP Header parse

## Contributing

1. Fork it ( https://github.com/bararchy/sniffer/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [bararchy](https://github.com/bararchy) Bar Hofesh - creator, maintainer
