# Periodically Check Mirrors of Tock-related Files

This script automatically (through GitHub actions) checks mirrors
holding Tock-related files (such as pre-built toolchains) and ensures
that they do not go down unnoticed. If an issue is detected, it
creates a GitHub issue and tags the admins of the respective mirror.

It is still missing a mechanism to automatically pull new URLs from
Tock repositories.

## Usage

The script maintains its list of mirrors in a `mirrors.json` file, and
the URLs it knows about it a `urls.json` file. Identical files on
different mirrors correspond to different URLs, but should have
identical checksum & size fields.

To add a new URL, run:

```sh
python3 mirrorcheck.py add-url -u urls.json -m mirrors.json 'https://example.org/files/archive.zip'
```

## License

Licensed under either of

- Apache License, Version 2.0 (LICENSE-APACHE or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
