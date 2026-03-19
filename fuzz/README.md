# Fuzzing

This directory contains libFuzzer targets, corpora, and small helper scripts.

## Build

```bash
CC=clang CXX=clang++ cmake -S . -B build-fuzz-clang -DENABLE_FUZZ=ON -DENABLE_ASAN=OFF -DENABLE_TSAN=OFF
cmake --build build-fuzz-clang -j2
```

## Run

```bash
./build-fuzz-clang/ch_parser_fuzz -dict=fuzz/ch_parser.dict -rss_limit_mb=2048 fuzz/corpus/ch_parser
./build-fuzz-clang/mux_codec_fuzz -dict=fuzz/mux_codec.dict -rss_limit_mb=2048 fuzz/corpus/mux_codec
```

## Corpus merge

```bash
./fuzz/merge_corpus.sh ch_parser fuzz/corpus/ch_parser_new fuzz/corpus/ch_parser
./fuzz/merge_corpus.sh mux_codec fuzz/corpus/mux_codec_new fuzz/corpus/mux_codec
```

## Crash replay

```bash
./fuzz/replay_crash.sh ch_parser crash-XXXXXXXXXXXXXXXX
./fuzz/replay_crash.sh mux_codec crash-XXXXXXXXXXXXXXXX
```
