# cert

[![Release](https://img.shields.io/github/release/alexdzyoba/cert.svg?style=flat-square)](https://github.com/alexdzyoba/cert/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)
[![Build status](https://github.com/alexdzyoba/cert/workflows/Go/badge.svg)](https://github.com/alexdzyoba/cert/actions)


Handy certificate tool.

Its core purpose is to print certificate(s) in the nice way. If it sees multiple
certificates it will try to verify them as a chain.

## Examples

It can print from file

![Example usage with file](.github/example-file.png)

Or from URL:

![Example usage with URL](.github/example-url.png)

## Installation

Download the file from the [latest release](https://github.com/alexdzyoba/cert/releases/latest).

## TODO

- [ ] Put full chain of certs into testdata to fixate root certs
