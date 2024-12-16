# m3u8-dl

下载m3u8视频文件并合并(要求装有ffmpeg)


## usage

```
Usage: m3u8-dl [OPTIONS] --url <URL> --dir <DIR> --name <NAME>

Options:
  -u, --url <URL>
          m3u8地址

  -d, --dir <DIR>
          输出文件夹

  -n, --name <NAME>
          输出文件名，必须以mp4或者mkv结尾

      --uid <UID>
          使用指定uid运行程序(unavailable for window)

  -t, --thread <THREAD>
          线程数量
          
          [default: 4]

      --daemon
          后台运行(unavailable for windows)

  -l, --log <LOG>
          日志文件位置

  -c, --clear
          完成删除中间文件

  -s, --skip <SKIP>
          跳过ts文件开头字节数
          
          [default: 0]

  -r, --retry <RETRY>
          下载重试次数
          
          [default: 3]

      --proxy <PROXY>
          代理,如127.0.0.1:7382

      --no-proxy
          如无该参数，将会尝试使用环境中的代理配置

      --ffmpeg <FFMPEG>
          ffmpeg可执行文件位置
          
          [default: ffmpeg]

      --replace-not-found
          当ts返回404时，使用最近的已下载的ts替换

  -v, --verbose
          输出更多日志

  -h, --help
          Print help (see a summary with '-h')
```

## 构建

rust版本 1.83.0

```shell
cargo build
```