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
```

## Corpus merge

```bash
./fuzz/merge_corpus.sh ch_parser fuzz/corpus/ch_parser_new fuzz/corpus/ch_parser
```

## Crash replay

```bash
./fuzz/replay_crash.sh ch_parser crash-XXXXXXXXXXXXXXXX
```
