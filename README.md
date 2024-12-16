# m3u8-dl

下载m3u8视频文件并合并(要求装有ffmpeg)


## usage

```
Usage: m3u8-dl [OPTIONS] --url <URL> --dir <DIR> --name <NAME>

Options:
      --url <URL>        m3u8地址
      --dir <DIR>        输出文件夹
  -n, --name <NAME>      输出文件位置
      --uid <UID>        使用权限uid
      --thred <THRED>    线程数量 [default: 4]
  -d                     后台运行
      --log <LOG>        配置输出到日志文件
      --delete           完成后删除ts文件
  -s, --skip <SKIP>      跳过ts文件开头字节数 [default: 0]
  -r, --retry <RETRY>    下载重试次数 [default: 3]
      --proxy <PROXY>    代理,如127.0.0.1:7382
      --no-proxy         不使用代理
      --ffmpeg <FFMPEG>  ffmpeg可执行文件位置 [default: ffmpeg]
  -h, --help             Print help
```

## 构建

最低rust版本 1.81.0

```shell
cargo build
```