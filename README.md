# ngrok-libev
The client for ngrok writing by libev

梅林上的 ngrok 版本。使用方式请看梅林固件。更多方法等我更新 readme

此版本特点：

1. 事件驱动，感谢 libev
2. 基于 json 来配置穿透，各种穿透的组合更方便

存在问题：

当时选用的内存池方案可能是一个败笔，现在内存管理并不好。未来会换成 jemalloc 或直接用 malloc

配置文件请看：tunnel/default.json
