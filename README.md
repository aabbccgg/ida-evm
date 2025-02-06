# IDA-EVM
[IDA](https://www.hex-rays.com/products/ida/) Processor Module for the [Ethereum Virtual Machine](https://github.com/trailofbits/evm-opcodes) (EVM).

This plugin is under active development. New issues and contributions are welcome, and are covered by bounties from Trail of Bits. Join us in #ethereum on the [Empire Hacking Slack](https://slack.empirehacking.nyc) to discuss Ethereum security tool development.

IDA Pro 7.0 with python3.0 or newer is required to use IDA-EVM.

![Screenshot](/images/screenshot.png)

# Installation
* Copy `evm-loader.py` to `%IDA%/loaders`
* Copy `evm-cpu.py` and `known_hashes.py` to `%IDA%/procs` （ida7 and windows）
* Restart IDA

# Installation for IDA9 & MacOS
* `%IDA%` path on MacOS: `/Applications/IDA Professional 9.0.app/Contents/MacOS`
* Copy `evm-loader.py` to `%IDA%/loaders`
* Copy `evm-cpu.py` to `%IDA%/procs`
* Copy `known_hashes.py` to `%IDA%/python`
* Restart IDA
