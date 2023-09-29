<img src="assets/gaia.png" width="300" align="right" alt="A vector silhouette of Gaia, the greek personification of Earth"/>

# Gaia

Gaia is a command-line application for encrypting and decrypting files.

<img src="assets/shell.png" width="600">

## Compiling

1. [Install Rust](https://rustup.rs/)
2. ```shell
   $ git clone https://github.com/bluelhf/gaia
   $ cargo build --release
   ```
3. The compiled binary is at `target/release/gaia`.

## Usage with Pithos

Gaia's GitHub repository comes with a POSIX shell
script for automatically encrypting a file with Gaia
and sending it to [Pithos](https://github.com/bluelhf/pithos).

```shell
$ /tmp/gaia/pithos upload <"Cargo.toml"
######################################################################## 100.0%
/tmp/gaia/pithos download CLXuz...7OgAw== 704bb29d-bbc0-455d-88e0-d0b96e25319e
```
```shell
$ /tmp/gaia/pithos download CLXuz...7OgAw== 704bb29d-bbc0-455d-88e0-d0b96e25319e
[package]
name = "gaia"
vers...
```
