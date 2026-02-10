# 测试流程

本项目测试分为构建、单元测试与集成测试三部分。

## 构建

```bash
cmake -S . -Bbuild && cmake --build build -j12
```

## 单元测试

```bash
ctest --test-dir build -j12 --output-on-failure
```

## 集成测试

```bash
python3 script/comprehensive_test.py
python3 script/setup_and_run_other_tests.py
```

## 注意事项

1. 测试前确保端口未被占用（如 1080/8844/9999/8888/14443/14444/14445）。
2. 集成测试会启动本地假 TLS 与 Echo 服务。
3. 若单测失败，优先查看对应测试日志与错误输出。
