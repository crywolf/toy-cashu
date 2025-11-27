# Cashu CLI wallet

Bitcoin Chaumian E-Cash wallet using [Cashu](https://cashu.space/) protocol. Implemented from scratch.

> [!CAUTION]
>
> Only for educational and testing purposes! Do not use with real Bitcoin, you would loose it!

## Implemented [NUTs](https://github.com/cashubtc/nuts/)

| NUT #    | Description             |
| -------- | ----------------------- |
| [00][00] | Cryptography and Models |
| [01][01] | Mint public keys        |
| [02][02] | Keysets and fees        |
| [03][03] | Swapping tokens         |
| [04][04] | Minting tokens          |
| [05][05] | Melting tokens          |
| [06][06] | Mint info               |
| [08][08] | Overpaid Lightning fees |
| [12][12] | DLEQ proofs             |
| [20][20] | Signature on Mint Quote |
| [23][23] | Payment Method: BOLT11   |

[00]: https://github.com/cashubtc/nuts/blob/main/00.md
[01]: https://github.com/cashubtc/nuts/blob/main/01.md
[02]: https://github.com/cashubtc/nuts/blob/main/02.md
[03]: https://github.com/cashubtc/nuts/blob/main/03.md
[04]: https://github.com/cashubtc/nuts/blob/main/04.md
[05]: https://github.com/cashubtc/nuts/blob/main/05.md
[06]: https://github.com/cashubtc/nuts/blob/main/06.md
[08]: https://github.com/cashubtc/nuts/blob/main/08.md
[12]: https://github.com/cashubtc/nuts/blob/main/12.md
[20]: https://github.com/cashubtc/nuts/blob/main/20.md
[23]: https://github.com/cashubtc/nuts/blob/main/23.md

## Usage

```shell
cargo run -- help
```

Start a mint or use public test mint ([Running a mint](https://github.com/cashubtc/nutshell?tab=readme-ov-file#running-a-mint))

```shell
cargo run -- create wallet1 http://localhost:3338
```

```shell
cargo run -- open wallet1
```

Inside opened wallet use `help` command:

```shell
wallet1> help
  Usage: <COMMAND>

Commands:
  balance    Display wallet balance
  info       Display wallet info
  mint-info  Get info about mint
  keys       Get mint keys
  keysets    Get mint keysets
  mint       Mint tokens
  melt       Melt tokens
  send       Generate Cashu V4 token
  receive    Receive via Cashu V4 token
  exit
  quit
  help       Print this message or the help of the given subcommand(s)
```
