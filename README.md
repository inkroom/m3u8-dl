# m3u8-dl

下载m3u8视频文件并合并(要求装有ffmpeg)


## usage

```
Usage: m3u8-dl [OPTIONS]

Options:
  -u, --url <URL>
          m3u8地址

  -d, --dir <DIR>
          输出文件夹

  -n, --name <NAME>
          输出文件名，必须以mp4或者mkv结尾

      --exclude <EXCLUDE>
          排除部分ts文件；json key=[e]

      --prefix <PREFIX>
          使用file协议时用于指定ts文件前缀；json key=[p]

      --header <HEADER>
          请求头，用法同curl

  -j, --json <JSON>
          读取json格式，例如[{"n":"1.mp4","u":"http://demo.com/1.m3u8","d":"/root"}]

      --json-file <JSON_FILE>
          从文件读取json格式

      --uid <UID>
          使用指定uid运行程序(unavailable on windows)

  -t, --thread <THREAD>
          线程数量
          
          [default: 4]

      --daemon
          后台运行

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
          当ts返回404时，使用最近的已下载的ts替换；如果启用多线程可能会导致替换失败或者源文件过于靠前

      --temp
          当文件数过多导致合并失败时，可以使用该参数借助临时文件合并视频

  -v, --verbose
          输出更多日志

  -h, --help
          Print help (see a summary with '-h')
```

一共三种使用方式，如果只需要下载单个视频，使用`-u`、`-d`、`-n`

如果下载大量视频，使用 json格式，样例如下
```json
[{"n":"1.mp4","u":"http://demo.com/1.m3u8","d":"/root"}]
```

通过`--json`直接传入json字符串，或者使用`--json-file`指定json文件位置，在unix上也可使用管道传递，例如`cat 1.json | m3u8-dl`

---

当同时下载大量视频时，不能保证一个视频下载完成后才开始下载下一个视频，如果需要该效果，改为执行多条命令，或者`--thread 1`（可能会拖累下载效率）

## 构建

rust版本 1.83.0

```shell
cargo build
```