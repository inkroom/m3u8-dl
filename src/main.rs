use std::fmt::Debug;
use std::sync::atomic::AtomicU32;
use std::time::SystemTime;
use std::{ffi::CString, sync::Arc};

use clap::Parser;
use crypto::digest::Digest;

use m3u8_rs::Playlist;

#[derive(Parser)]
pub struct Cli {
    #[arg(short, long = "url", help = "m3u8地址")]
    url: Option<String>,
    #[arg(short, long = "dir", help = "输出文件夹")]
    dir: Option<String>,
    #[arg(short, long, help = "输出文件名，必须以mp4或者mkv结尾")]
    name: Option<String>,
    #[arg(
        short,
        long,
        help = "读取json格式",
        long_help = "读取json格式，例如[{\"n\":\"1.mp4\",\"u\":\"http://demo.com/1.m3u8\",\"d\":\"/root\"}]"
    )]
    json: Option<String>,
    #[arg(long, help = "从文件读取json格式")]
    json_file: Option<String>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[arg(long, help = "使用指定uid运行程序(unavailable on windows)")]
    uid: Option<u32>,
    #[arg(short, long, default_value = "4", help = "线程数量")]
    thread: u32,
    #[arg(long, help = "后台运行", default_value = "false")]
    daemon: bool,
    #[arg(short, long, help = "日志文件位置")]
    log: Option<String>,
    #[arg(short, long, help = "完成删除中间文件", default_value = "false")]
    clear: bool,
    #[arg(short, long, help = "跳过ts文件开头字节数", default_value = "0")]
    skip: usize,
    #[arg(short, long, help = "下载重试次数", default_value = "3")]
    retry: usize,
    #[arg(long, help = "代理,如127.0.0.1:7382")]
    proxy: Option<String>,
    #[arg(
        long,
        help = "不使用代理",
        default_value = "false",
        long_help = "如无该参数，将会尝试使用环境中的代理配置"
    )]
    no_proxy: bool,
    #[arg(long, help = "ffmpeg可执行文件位置", default_value = "ffmpeg")]
    ffmpeg: String,
    #[arg(
        long,
        help = "处理404",
        long_help = "当ts返回404时，使用最近的已下载的ts替换；如果启用多线程可能会导致替换失败或者源文件过于靠前",
        default_value = "false"
    )]
    replace_not_found: bool,

    #[arg(short, long, default_value = "false", help = "输出更多日志")]
    verbose: bool,
}

impl Debug for Cli {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opt")
            .field("url", &self.url.as_deref().unwrap_or(""))
            .field("dir", &self.dir.as_deref().unwrap_or(""))
            .field("name", &self.name.as_deref().unwrap_or(""))
            .field("log", &self.log.as_deref().unwrap_or(""))
            .field("thread", &self.thread)
            .field("skip", &self.skip)
            .field("retry", &self.retry)
            .field("ffmpeg", &self.ffmpeg)
            .field("proxy", &self.proxy.as_deref().unwrap_or(""))
            .field("no_proxy", &self.proxy.as_deref().unwrap_or(""))
            .field("verbose", &self.verbose)
            .finish()
    }
}
impl Cli {
    pub(crate) fn get_m3u8(&self) -> Result<Vec<Item>, String> {
        if let Some(json) = &self.json {
            json::read_json(json.as_str())
        } else if let Some(f) = &self.json_file {
            let v = std::fs::read(f.as_str())
                .map_err(|e| format!("read json_file fail, reason:{}", e))
                .and_then(|v| String::from_utf8(v).map_err(|_e| format!("only support utf8")))?;
            json::read_json(v.as_str())
        } else if self.url.is_some() && self.name.is_some() && self.dir.is_some() {
            Ok(vec![Item::new(
                self.name.clone().unwrap().as_str(),
                self.dir.clone().unwrap().as_str(),
                self.url.clone().unwrap().as_str(),
            )?])
        } else {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                use std::io::Read;
                unsafe {
                    // 把输入流读取变成非阻塞的，方便支持管道
                    libc::fcntl(libc::STDIN_FILENO, libc::F_SETFL, libc::O_NONBLOCK);
                }

                let mut stdin = std::io::stdin();
                let mut v = String::new();

                if let Ok(_) = stdin.read_to_string(&mut v) {
                    log::debug!("read from stdin,value={v}");
                    return json::read_json(v.as_str());
                }
            }

            Err(format!("(url,name,dir) or json or json_file must be used"))
        }
    }
}
struct Item {
    name: String,
    dir: String,
    url: String,
}

impl Item {
    pub(crate) fn new(name: &str, dir: &str, url: &str) -> Result<Self, String> {
        if !name.ends_with(".mp4") && !name.ends_with(".mkv") {
            Err("name 必须有文件格式".to_string())
        } else {
            Ok(Item {
                name: name.to_string(),
                dir: dir.to_string(),
                url: url.to_string(),
            })
        }
    }
}

struct Opt {
    m3u8: Vec<Item>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    uid: Option<u32>,
    thread: u32,
    clear: bool,
    skip: usize,
    retry: usize,
    ffmpeg: String,
    replace_not_found: bool,
    client: Option<Box<dyn HttpClient + Send + Sync>>,
    begin: Option<std::time::SystemTime>,
}

mod json {
    use crate::Item;

    /// 左中括号 [
    const VALUE_MIDDLE_LEFT: usize = 1;
    /// 右中括号
    const VALUE_MIDDLE_RIGHT: usize = 2;
    /// 左大括号
    const VALUE_LARGE_LEFT: usize = 4;
    /// 右大括号
    const VALUE_LARGE_RIGHT: usize = 8;
    /// 引号
    const VALUE_QUOTE: usize = 16;
    /// 换行，制表符，空格等空白字符
    const VALUE_SPACE: usize = 32;
    /// 冒号
    const VALUE_COLON: usize = 64;
    /// 逗号
    const VALUE_COMMA: usize = 128;
    /// 开始
    const VALUE_BEGIN: usize = 256;
    /// 结束
    // const VALUE_END: usize = 512;
    /// 普通值
    const VALUE: usize = 1024;

    struct TempValue {
        name: Option<String>,
        dir: Option<String>,
        url: Option<String>,
    }

    impl TempValue {
        fn is_complete(&self) -> bool {
            self.name.is_some() && self.dir.is_some() && self.url.is_some()
        }

        fn is_none(&self) -> bool {
            self.name.is_none() && self.url.is_none() && self.dir.is_none()
        }

        fn as_value(&self) -> Result<Item, String> {
            Item::new(
                self.name.clone().unwrap().as_str(),
                self.dir.clone().unwrap().as_str(),
                self.url.clone().unwrap().as_str(),
            )
        }
        fn clear(&mut self) {
            self.name = None;
            self.dir = None;
            self.url = None;
        }
    }
    ///
    /// # Returns
    /// - name
    /// - dir
    /// - url
    pub(crate) fn read_json(json: &str) -> Result<Vec<Item>, String> {
        let mut vec = Vec::new();
        let s: Vec<char> = json.chars().collect();
        let mut now = 0;
        let mut except = VALUE_BEGIN | VALUE_MIDDLE_LEFT | VALUE_SPACE;
        let mut item = TempValue {
            name: None,
            dir: None,
            url: None,
        };
        let mut key = None;
        while now < s.len() {
            let current = s[now];
            let p = parse_value(current) & except;
            if p == 0 {
                // 不允许
                return Err(format!("unexcept char [{}] at {now}", current));
            }
            now += 1;

            match p {
                VALUE_BEGIN => {
                    except = VALUE_MIDDLE_LEFT | VALUE_SPACE;
                }
                VALUE_MIDDLE_LEFT => {
                    except = VALUE_SPACE | VALUE_LARGE_LEFT;
                }
                VALUE_SPACE => {}
                VALUE_LARGE_LEFT => {
                    except = VALUE_QUOTE | VALUE_SPACE;
                }
                VALUE_QUOTE => {
                    except = VALUE;
                    let mut temp = String::new();

                    // 读取到下一个引号
                    let mut next = now;
                    while next < s.len() {
                        let t = s[next];
                        if parse_value(t) & VALUE_QUOTE != VALUE_QUOTE {
                            temp.push(t);
                            next += 1;
                        } else {
                            now = next + 1;
                            // 读取完了
                            if key.is_none() {
                                key = Some(temp);
                                except = VALUE_COLON | VALUE_SPACE;
                            } else if let Some(t) = &key {
                                // value
                                if t == "n" {
                                    if item.name.is_some() {
                                        return Err(format!("Duplicate object key [{}]", t));
                                    }
                                    item.name = Some(temp);
                                } else if t == "d" {
                                    if item.dir.is_some() {
                                        return Err(format!("Duplicate object key [{}]", t));
                                    }
                                    item.dir = Some(temp);
                                } else if t == "u" {
                                    if item.url.is_some() {
                                        return Err(format!("Duplicate object key [{}]", t));
                                    }
                                    item.url = Some(temp);
                                } else {
                                    return Err(format!("unsupport key: {t}"));
                                }
                                key = None;
                                if item.is_complete() {
                                    // 读完一个item，再多的key，这里也不支持了
                                    except = VALUE_COMMA | VALUE_LARGE_RIGHT | VALUE_SPACE;
                                } else {
                                    // 读完一对kv，但是还不够一个item，说明应该继续读一个key，
                                    except = VALUE_COMMA | VALUE_SPACE;
                                }
                            }
                            break;
                        }
                    }
                    if next == s.len() {
                        return Err(format!("unvalid json"));
                    }
                }
                VALUE_COLON => {
                    except = VALUE_QUOTE | VALUE_SPACE;
                }
                VALUE_COMMA => {
                    if except & VALUE_MIDDLE_RIGHT == VALUE_MIDDLE_RIGHT {
                        // 已经读完了一个item
                        except = VALUE_MIDDLE_RIGHT | VALUE_LARGE_LEFT | VALUE_SPACE;
                    } else {
                        // 应该读key
                        except = VALUE_QUOTE | VALUE_SPACE;
                    }
                }
                VALUE_LARGE_RIGHT => {
                    if item.is_none() {
                        return Err(format!("unvalid json, need more info"));
                    }
                    // 读完一个item
                    vec.push(item.as_value()?);
                    item.clear();

                    except = VALUE_COMMA | VALUE_MIDDLE_RIGHT | VALUE_SPACE;
                }
                VALUE_MIDDLE_RIGHT => {
                    // 结束了，此时应该没有临时数据
                    if !item.is_none() || !key.is_none() {
                        return Err(format!("unvalid json"));
                    }
                }
                VALUE => {
                    // temp.push(current);
                    // now += 1;
                }

                _ => {
                    break;
                }
            }
        }

        Ok(vec)
    }

    fn parse_value(v: char) -> usize {
        match v {
            '[' => VALUE_MIDDLE_LEFT,
            ']' => VALUE_MIDDLE_RIGHT,
            '{' => VALUE_LARGE_LEFT,
            '}' => VALUE_LARGE_RIGHT,
            '"' => VALUE_QUOTE,
            ',' => VALUE_COMMA,
            ':' => VALUE_COLON,
            '\n' => VALUE_SPACE,
            ' ' => VALUE_SPACE,
            '\t' => VALUE_SPACE,
            _ => 0,
        }
    }
    #[cfg(test)]
    mod tests {
        use super::read_json;

        #[test]
        fn test() {
            let v = r#"[{"n":"name.mp4","u":"url","d":"d"}]"#;
            let s = read_json(v).unwrap();
            assert_eq!(1, s.len());
            assert_eq!("name.mp4", s[0].name);
            assert_eq!("d", s[0].dir);
            assert_eq!("url", s[0].url);

            let v = r#"[{"n":"name.mp4","u":"url","d":"d"}]"#;
            let s = read_json(v).unwrap();
            assert_eq!(1, s.len());
            assert_eq!("name.mp4", s[0].name);
            assert_eq!("d", s[0].dir);
            assert_eq!("url", s[0].url);

            let v = r#"[{"n":"name.mp4","u":"url","d":"d"}]"#;
            let s = read_json(v).unwrap();
            assert_eq!(1, s.len());
            assert_eq!("name.mp4", s[0].name);
            assert_eq!("d", s[0].dir);
            assert_eq!("url", s[0].url);

            let v = r#"[{"n":"name.mp4",
            "u":"url","d":"d"},
]"#;
            let s = read_json(v).unwrap();
            assert_eq!(1, s.len());
            assert_eq!("name.mp4", s[0].name);
            assert_eq!("d", s[0].dir);
            assert_eq!("url", s[0].url);

            let v = r#"[{"n":"name.mp4","u":"url","d":"d"},
            ]"#;
            let s = read_json(v).unwrap();
            assert_eq!(1, s.len());
            assert_eq!("name.mp4", s[0].name);
            assert_eq!("d", s[0].dir);
            assert_eq!("url", s[0].url);

            let v = r#"[{"n" : "name.mp4", "u":"url","d":"d"}]"#;
            let s = read_json(v).unwrap();
            assert_eq!(1, s.len());
            assert_eq!("name.mp4", s[0].name);
            assert_eq!("d", s[0].dir);
            assert_eq!("url", s[0].url);

            let v =
                r#"[{"n" : "name.mp4", "u":"url","d":"d"},{"n" : "name.mp4", "u":"url","d":"d"}]"#;
            let s = read_json(v).unwrap();
            assert_eq!(2, s.len());
            assert_eq!("name.mp4", s[0].name);
            assert_eq!("d", s[0].dir);
            assert_eq!("url", s[0].url);
        }

        #[test]
        fn mul() {
            let v =
                r#"[{"n" : "name.mp4", "u":"url","d":"d"},{"n" : "name.mp4", "u":"url","d":"d"}]"#;
            let s = read_json(v).unwrap();
            assert_eq!(2, s.len());
            assert_eq!("name.mp4", s[0].name);
            assert_eq!("d", s[0].dir);
            assert_eq!("url", s[0].url);
        }

        #[test]
        #[should_panic]
        fn duplicate() {
            let v =
                r#"[{"n" : "name.mp4", "u":"url","d":"d"},{"n" : "name.mp4", "u":"url","u":"d"}]"#;
            let s = read_json(v).unwrap();
            assert_eq!(2, s.len());
            assert_eq!("name.mp4", s[0].name);
            assert_eq!("d", s[0].dir);
            assert_eq!("url", s[0].url);
        }
    }
}
mod threadpool {
    use std::{
        sync::{mpsc::channel, Arc, Mutex},
        thread,
        thread::JoinHandle,
    };

    // 包装匿名函数类型
    // type Workfn<T> = Fn(Box<T>, &Arc<Sender<T>>) -> () + Send + Sync;
    // 区分工作和停机消息
    enum Msg<T> {
        Work(Box<T>),
        Down,
    }
    // 使用Msg命名空间
    use Msg::*;

    pub struct Sender<T> {
        inner: std::sync::mpsc::Sender<Msg<T>>,
        count: usize,
    }

    impl<T> Sender<T> {
        pub fn send(&self, value: T) {
            self.inner.send(Work(Box::new(value))).unwrap();
        }

        pub fn shutdown(&self) {
            self.inner.send(Down).unwrap();
        }

        pub fn shutdown_all(&self) {
            for _ in 0..self.count {
                self.inner.send(Down).unwrap();
            }
        }
    }

    // 主构造函数Concurrent
    pub struct Concur<T> {
        count: usize,                         // 线程数量
        sender: Arc<Sender<T>>,               // 异步发送器
        threads: Option<Vec<JoinHandle<()>>>, // 带有 原子指针 异步接收器 的线程 列表
    }

    impl<T: Send + Sync + 'static> Concur<T> {
        // 初始化函数
        pub fn new<F>(count: usize, fun: F) -> Self
        where
            F: Fn(Box<T>, &Arc<Sender<T>>),
            F: Sync,
            F: Send + 'static,
        {
            let mut threads = Vec::with_capacity(count);
            let (sender, receiver) = channel();
            let sender = Arc::new(Sender {
                inner: sender,
                count,
            });
            let receiver = Arc::new(Mutex::new(receiver));
            let arc_fn = Arc::new(fun);
            for i in 0..count {
                let p_rec = Arc::clone(&receiver);
                let arc_fn = Arc::clone(&arc_fn);
                let sender = Arc::clone(&sender);

                threads.push(thread::spawn(move || loop {
                    let f: Msg<T> = p_rec.lock().unwrap().recv().unwrap();
                    match f {
                        Work(v) => {
                            log::debug!("thread {i} start work");
                            arc_fn(v, &sender);
                        }
                        Down => {
                            break;
                        }
                    };
                }));
            }
            Concur {
                count,
                sender,
                threads: Some(threads),
            }
        }

        pub fn push(&self, f: T) {
            self.sender.send(f);
        }

        pub fn wait(&mut self) {
            for thread in self.threads.take().unwrap() {
                thread.join().unwrap();
            }
        }
    }

    impl<T> Drop for Concur<T> {
        fn drop(&mut self) {
            // 发送停机消息
            for i in 0..self.count {
                if let Some(t) = self.threads.as_ref() {
                    if !t[i].is_finished() {
                        self.sender.shutdown();
                    }
                }
            }
            if self.threads.is_some() {
                // 等待所有线程运行完毕
                for thread in self.threads.take().unwrap() {
                    thread.join().unwrap();
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::Concur;

        #[test]
        fn test() {
            let v: Concur<usize> = Concur::new(2, |v, se| {
                println!("value = {}", v);
            });
            for i in 39..542 {
                v.push(i);
            }
        }
    }
}
pub trait HttpClient: Send {
    fn init(opt: &Cli) -> Result<Self, String>
    where
        Self: Sized;

    fn get(&self, url: &str) -> Result<Vec<u8>, (String, u16)>;
}

#[cfg(feature = "ureq")]
mod ureqclient {
    use crate::{Cli, HttpClient};

    pub(crate) struct UReqClient {
        inner: ureq::Agent,
    }

    impl HttpClient for UReqClient {
        fn init(opt: &Cli) -> Result<Self, std::string::String> {
            let mut bu = ureq::AgentBuilder::new();
            if !opt.no_proxy {
                if let Some(proxy) = &opt.proxy {
                    log::debug!("use proxy = {}", proxy);
                    bu = bu.proxy(
                        ureq::Proxy::new(proxy).map_err(|e| format!("unvalid proxy {}", proxy))?,
                    );
                } else {
                    log::debug!("use env proxy");
                    bu = bu.try_proxy_from_env(true);
                }
            } else {
                log::debug!("no proxy");
                bu = bu.try_proxy_from_env(false);
            }
            Ok(UReqClient { inner: bu.build() })
        }

        fn get(&self, url: &str) -> Result<Vec<u8>, (String, u16)> {
            let v = self.inner.get(url).call().map_err(|e| {
                (
                    format!("request error ={}", e),
                    e.into_response().map(|f| f.status()).unwrap_or(0),
                )
            })?;
            if v.status() == 200 {
                // let len: usize = match v.header("content-length").and_then(|f| f.parse().ok()) {
                //     Some(v) => v,
                //     None => return Err(("request no content-length".to_string(), v.status())),
                // };
                // TODO 这里会吃掉一些响应头，很奇怪
                let mut bytes: Vec<u8> = Vec::new();
                v.into_reader()
                    .read_to_end(&mut bytes)
                    .map_err(|e| (format!("reqeust fail , reason = [{}]", e), 200))?;
                return Ok(bytes);
            }
            Err((
                format!("request fail, reason = [{}]", v.status_text()),
                v.status(),
            ))
        }
    }
}
#[cfg(feature = "west")]
mod reqwestclient {
    use crate::HttpClient;

    pub struct ReqWestClient {
        inner: reqwest::blocking::Client,
    }

    impl HttpClient for ReqWestClient {
        fn init(opt: &crate::Cli) -> Result<Self, String>
        where
            Self: Sized,
        {
            let mut c = reqwest::blocking::Client::builder();
            if !opt.no_proxy {
                if let Some(proxy) = &opt.proxy {
                    log::debug!("use proxy = {}", proxy);
                    c = c.no_proxy().proxy(
                        reqwest::Proxy::all(proxy)
                            .unwrap_or_else(|_| panic!("unvalid proxy = {}", proxy)),
                    );
                } else {
                    log::debug!("will use the env proxy config");
                    // log::info!("use proxy ={proxy}");
                    // c = c.proxy(reqwest::Proxy::all(proxy_scheme))
                }
            } else {
                log::debug!("no proxy");
                c = c.no_proxy();
            }
            c.build()
                .map(|f| ReqWestClient { inner: f })
                .map_err(|f| format!("init fail {f}"))
        }

        fn get(&self, url: &str) -> Result<Vec<u8>, (String, u16)> {
            match self.inner.get(url).send().map_err(|e| e.to_string()) {
                Ok(v) => {
                    let status = v.status();
                    if status.is_success() {
                        v.bytes().map(|f| f.to_vec()).map_err(|f| {
                            (
                                format!("request {url} fail , reason:{}", f),
                                status.as_u16(),
                            )
                        })
                    } else {
                        Err((
                            format!("request {url} fail, reason: {}", v.status().as_u16()),
                            v.status().as_u16(),
                        ))
                    }
                }
                Err(e) => Err((e, 0)),
            }
        }
    }
}

enum Task {
    M3u8 {
        name: String,
        url: String,
        dir: String,
    },
    Ts {
        key: Option<m3u8_rs::Key>,
        url: String,
        path: String,
        dir: String,
        files: Arc<Vec<String>>,
        index: usize,
        out: String,
        count: Arc<AtomicU32>,
    },
}

#[cfg(target_os = "windows")]
fn start_daemon(_opt: Opt) {
    log::info!("the download task will continue on daemon");
    use std::os::windows::process::CommandExt;
    let args = std::env::args();
    // 必须排除 --daemon 参数
    let mut args = args.filter(|f| f != "--daemon").collect::<Vec<String>>();
    let program = args.remove(0);
    // https://rustwiki.org/zh-CN/std/os/windows/process/trait.CommandExt.html#tymethod.creation_flags
    // 使用 CREATE_NEw_PROCESS_GROUP= 0x00000200，实际上不用这个也行，但是这个好像跟ctrl+c信号有关
    std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(0x00000200)
        .spawn()
        .unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn start_daemon(opt: Opt) {
    unsafe {
        let pid = libc::fork();
        if pid > 0 {
            // println!("父进程结束 {}", std::process::id());
            log::info!("the download task will continue on daemon");
            return;
        } else if pid == 0 {
            libc::setsid();
            let _ = libc::close(0);
            let _ = libc::close(1);
            let _ = libc::close(2);
            // 重定向输入输出到/dev/null，否则子进程的控制台输出依然会打印出来
            let null = CString::new("/dev/null").unwrap();
            let null_fd = libc::open(null.as_ptr() as *const libc::c_char, libc::O_RDWR);
            if null_fd < 0 {
                panic!("子进程启动失败");
            }

            libc::dup2(null_fd, libc::STDIN_FILENO);
            libc::dup2(null_fd, libc::STDOUT_FILENO);
            libc::dup2(null_fd, libc::STDERR_FILENO);

            match opt.run() {
                Ok(_) => {}
                Err(e) => {
                    log::error!("{e}");
                    std::process::exit(101);
                }
            }
            return;
        } else {
            log::error!("fork 失败");
            return;
        }
    }
}
fn main() {
    let cli = Cli::parse();

    let opt = match Opt::new(&cli) {
        Ok(v) => v,
        Err(e) => {
            log::error!("{e}");
            std::process::exit(101);
        }
    };

    if cli.daemon {
        start_daemon(opt);
        return;
    } else {
        match opt.run() {
            Ok(_) => {}
            Err(e) => {
                log::error!("{e}");
                std::process::exit(101);
            }
        }
    }
}

fn hex_string_to_bytes(hex_string: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chars = hex_string.chars().peekable();

    while let Some(c1) = chars.next() {
        if let Some(c2) = chars.next() {
            let byte = match u8::from_str_radix(&format!("{}{}", c1, c2), 16) {
                Ok(byte) => byte,
                Err(_) => {
                    log::warn!("decrypt fail, not valid iv");
                    return None;
                }
            };
            bytes.push(byte);
        } else {
            log::warn!("decrypt fail, not valid iv");
            return None;
        }
    }

    Some(bytes)
}

use crypto::aes;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::symmetriccipher::SymmetricCipherError;

/// Decrypt a buffer with the given key and iv using AES128/CBC/Pkcs encryption.
/// 解密(data:加密数据；key：密钥（长度为16的字符串）；iv：偏移量（长度为16的字符串）)
fn aes128_cbc_decrypt(
    data: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
) -> Result<Vec<u8>, SymmetricCipherError> {
    log::debug!("do decrypt");
    let mut decryptor = aes::cbc_decryptor(aes::KeySize::KeySize128, key, iv, PkcsPadding);

    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);
    let mut read_buffer = RefReadBuffer::new(data);
    let mut final_result = Vec::new();

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .copied(),
        );
        match result {
            crypto::buffer::BufferResult::BufferUnderflow => break,
            _ => continue,
        }
    }
    Ok(final_result)
}

mod custom_log {
    use crate::Cli;

    use std::{io::Write, time::Duration};
    /// 时间戳转换，从1970年开始
    pub(crate) fn time_display(value: u64) -> String {
        do_time_display(value, 1970, Duration::from_secs(8 * 60 * 60))
    }

    /// 时间戳转换，支持从不同年份开始计算
    pub(crate) fn do_time_display(value: u64, start_year: u64, timezone: Duration) -> String {
        // 先粗略定位到哪一年
        // 以 365 来计算，年通常只会相比正确值更晚，剩下的秒数也就更多，并且有可能出现需要往前一年的情况
        let value = value + timezone.as_secs();

        let per_year_sec = 365 * 24 * 60 * 60; // 平年的秒数

        let mut year = value / per_year_sec;
        // 剩下的秒数，如果这些秒数 不够填补闰年，比如粗略计算是 2024年，还有 86300秒，不足一天，那么中间有很多闰年，所以 年应该-1，只有-1，因为-2甚至更多 需要 last_sec > 365 * 86400，然而这是不可能的
        let last_sec = value - (year) * per_year_sec;
        year += start_year;

        let mut leap_year_sec = 0;
        // 计算中间有多少闰年，当前年是否是闰年不影响回退，只会影响后续具体月份计算
        for y in start_year..year {
            if is_leap(y) {
                // 出现了闰年
                leap_year_sec += 86400;
            }
        }
        if last_sec < leap_year_sec {
            // 不够填补闰年，年份应该-1
            year -= 1;
            // 上一年是闰年，所以需要补一天
            if is_leap(year) {
                leap_year_sec -= 86400;
            }
        }
        // 剩下的秒数
        let mut time = value - leap_year_sec - (year - start_year) * per_year_sec;

        // 平年的月份天数累加
        let mut day_of_year: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

        // 找到了 计算日期
        let sec = time % 60;
        time /= 60;
        let min = time % 60;
        time /= 60;
        let hour = time % 24;
        time /= 24;

        // 计算是哪天，因为每个月不一样多，所以需要修改
        if is_leap(year) {
            day_of_year[1] += 1;
        }
        let mut month = 0;
        for (index, ele) in day_of_year.iter().enumerate() {
            if &time < ele {
                month = index + 1;
                time += 1; // 日期必须加一，否则 每年的 第 1 秒就成了第0天了
                break;
            }
            time -= ele;
        }

        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            year, month, time, hour, min, sec
        )
    }
    //
    // 判断是否是闰年
    //
    fn is_leap(year: u64) -> bool {
        year % 4 == 0 && ((year % 100) != 0 || year % 400 == 0)
    }
    ///
    /// 输出当前时间格式化
    ///
    /// 例如：
    /// 2023-09-28T09:32:24Z
    ///
    pub(crate) fn time_format() -> String {
        // 获取当前时间戳
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|v| v.as_secs())
            .unwrap_or(0);

        time_display(time)
    }
    struct Writer {
        console: std::io::Stdout,
        fs: Option<std::fs::File>,
    }
    impl Writer {
        pub fn new(opt: &Cli) -> Self {
            Writer {
                console: std::io::stdout(),
                fs: opt.log.as_ref().map(|f| {
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(f.as_str())
                        .unwrap()
                }),
            }
        }
    }
    impl Write for Writer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Some(fs) = &mut self.fs {
                self.console.write(buf)?;
                fs.write(buf)
            } else {
                self.console.write(buf)
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if let Some(fs) = &mut self.fs {
                self.console.flush()?;
                fs.flush()
            } else {
                self.console.flush()
            }
        }
    }
    pub(crate) fn init(opt: &Cli) -> Result<(), String> {
        if opt.verbose {
            std::env::set_var("RUST_LOG", "debug");
        } else {
            std::env::set_var("RUST_LOG", "info");
        }

        let mut s = env_logger::builder();
        s.default_format()
            .parse_default_env()
            .format(|buf, record| writeln!(buf, "{}: {}", time_format(), record.args()))
            .target(env_logger::Target::Pipe(Box::new(Writer::new(opt))));
        if opt.verbose {
            s.filter(Some("rustls"), log::LevelFilter::Off);
        }
        s.init();
        Ok(())
    }
}

impl Opt {
    fn new(cli: &Cli) -> Result<Self, String> {
        custom_log::init(cli)?;

        Ok(Self {
            m3u8: cli.get_m3u8()?,
            thread: cli.thread,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            uid: cli.uid,
            clear: cli.clear,
            skip: cli.skip,
            retry: cli.retry,
            ffmpeg: cli.ffmpeg.clone(),
            replace_not_found: cli.replace_not_found,
            #[cfg(feature = "ureq")]
            client: Some(Box::new(ureqclient::UReqClient::init(cli)?)),
            #[cfg(feature = "west")]
            client: Some(Box::new(reqwestclient::ReqWestClient::init(cli)?)),

            begin: Some(SystemTime::now()),
        })
    }

    fn run(self) -> Result<(), String> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(uid) = self.uid {
            unsafe {
                let _ = libc::setgid(uid);
                let _ = libc::setuid(uid);
            }
        }
        let b = self.begin.unwrap();
        self.create_queue()?;

        log::info!(
            "下载完成 耗时 ={}秒",
            SystemTime::now().duration_since(b).unwrap().as_secs()
        );
        Ok(())
    }
    fn get_m3u8_ts_url(
        &self,
        url: &str,
        uri: &str,
    ) -> Result<Vec<(Option<m3u8_rs::Key>, String)>, String> {
        let m3u8_url = url::Url::parse(url)
            .and_then(|f| f.join(uri))
            .map_err(|e| format!("m3u8 url not valid {}", e))?;
        log::info!("downloading m3u8 {}", m3u8_url);

        match self.download_inner(m3u8_url.as_str()) {
            Ok(v) => {
                match m3u8_rs::parse_playlist_res(v.as_ref()) {
                    Ok(Playlist::MasterPlaylist(m)) => {
                        let mut v = Vec::new();
                        for ele in &m.variants {
                            v.append(
                                &mut self.get_m3u8_ts_url(m3u8_url.as_str(), ele.uri.as_str())?,
                            );
                        }
                        Ok(v)
                    }
                    Ok(Playlist::MediaPlaylist(me)) => {
                        // 如果有需要解密的key，这个key只会出现在第0个ts上，但是每个ts都需要用

                        let key = me.segments[0].key.clone();

                        Ok(me
                            .segments
                            .iter()
                            .map(|f| {
                                (
                                    key.clone(),
                                    Self::get_real_url(m3u8_url.as_str(), f.uri.as_str()),
                                )
                            })
                            .filter(|f| f.1.is_ok())
                            .map(|f| (f.0, f.1.unwrap().to_string()))
                            .collect::<Vec<(Option<m3u8_rs::Key>, String)>>())
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
            Err((e, status)) => Err(format!("resp error {} {} {e}", status, m3u8_url)),
        }
    }

    fn start_m3u8(
        se2: &Arc<Opt>,
        sender: &Arc<threadpool::Sender<Task>>,
        name: String,
        url: String,
        dir: String,
    ) -> Result<bool, String> {
        // log::debug!("thread {i} {url}",);
        let out = format!("{}/{}", dir, name);
        let dir = format!("{}/{}", dir, name.replace(".mp4", "").replace(".mkv", ""));

        if std::fs::exists(out.as_str()).unwrap_or(false) {
            log::info!("the video file exists = [{out}] ");
            return Ok(false);
        }

        for c in 0..se2.thread {
            match se2.get_m3u8_ts_url(url.as_str(), "") {
                Ok(ts) => {
                    if let Err(e) = std::fs::create_dir_all(dir.as_str()) {
                        log::error!("create dir fail {e}");
                        return Err("fail".to_string());
                    };

                    let files: Arc<Vec<String>> = Arc::new(
                        ts.iter()
                            .enumerate()
                            .map(|(index, _)| format!("{dir}/{}.ts", index + 1))
                            .collect(),
                    );
                    let mut index = 0;
                    let count = std::sync::Arc::new(AtomicU32::new(files.len() as u32));
                    for (key, url) in ts {
                        index += 1;
                        let file = format!("{dir}/{}.ts", index);
                        sender.send(Task::Ts {
                            key,
                            url,
                            path: file,
                            dir: dir.clone(),
                            files: Arc::clone(&files),
                            index,
                            out: out.clone(),
                            count: std::sync::Arc::clone(&count),
                        });
                    }
                    return Ok(true);
                }
                Err(e) => {
                    log::error!("get m3u8 file fail after retry {c}, reason: [{e}]");
                    if c == se2.thread - 1 {
                        return Err("fail".to_string());
                    }
                }
            }
        }
        Ok(false)
    }

    fn create_queue(self) -> Result<(), String> {
        let m3u8_count: Arc<AtomicU32> = Arc::new(AtomicU32::new((&self.m3u8).len() as u32));
        let m3u8_fail_count: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let m3u8_fail_count2: Arc<AtomicU32> = Arc::clone(&m3u8_fail_count);

        let se = Arc::new(self);
        let se2 = Arc::clone(&se);
        let mut pool: threadpool::Concur<Task> =
            threadpool::Concur::new(se.thread as usize, move |task, sender| {
                #[inline]
                fn finish_m3u8(
                    m3u8_count: &Arc<AtomicU32>,
                    sender: &Arc<threadpool::Sender<Task>>,
                ) {
                    let v = m3u8_count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    // 退出线程
                    if v == 1 {
                        // 最后一个任务，直接退出所有线程
                        sender.shutdown_all();
                    }
                }

                match *task {
                    Task::M3u8 { name, url, dir } => {
                        match Self::start_m3u8(&se2, sender, name, url, dir) {
                            Ok(started) => {
                                if !started {
                                    finish_m3u8(&m3u8_count, sender);
                                }
                            }
                            Err(_) => {
                                finish_m3u8(&m3u8_count, sender);
                            }
                        }
                    }
                    Task::Ts {
                        key,
                        url,
                        path,
                        dir,
                        files,
                        index,
                        out,
                        count,
                    } => {
                        for i in 0..se2.retry {
                            if let Err(e) = se2.download_item(
                                &key,
                                url.as_str(),
                                path.as_str(),
                                dir.as_str(),
                                files.len()
                                    - count.load(std::sync::atomic::Ordering::SeqCst) as usize,
                                files.len(),
                                index,
                            ) {
                                log::error!(
                            "download file fail ={url}, reason =[{e}] after retry {i} count"
                        );
                            } else {
                                // 成功
                                break;
                            }
                        }
                        // 最后一个ts文件
                        let v = count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                        if v == 1 {
                            log::info!("ts file download complete, ready for concat to {out}");
                            if let Err(e) = se2.concat(files, out.as_str()) {
                                log::error!("concat video fail, reason: {e}");
                                m3u8_fail_count2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                            finish_m3u8(&m3u8_count, sender);
                        }
                    }
                }
            });
        for ele in &se.m3u8 {
            pool.push(Task::M3u8 {
                name: ele.name.clone(),
                url: ele.url.clone(),
                dir: ele.dir.clone(),
                // client: Arc::clone(&client),
            });
        }

        pool.wait();
        let s = m3u8_fail_count.load(std::sync::atomic::Ordering::Acquire);
        if s != 0 {
            // 有m3u8下载失败
            return Err("download complete, some video fail".to_string());
        }
        Ok(())
    }

    fn get_real_url(m3u8: &str, uri: &str) -> Result<String, String> {
        if uri.starts_with("http") {
            Ok(uri.to_string())
        } else {
            let url = url::Url::parse(m3u8).map_err(|e| e.to_string())?;

            url.join(uri)
                .map_or_else(|e| Err(e.to_string()), |f| Ok(f.as_str().to_string()))
        }
    }

    fn download_inner(&self, url: &str) -> Result<Vec<u8>, (String, u16)> {
        match &self.client {
            Some(c) => c.get(url),
            None => unreachable!(),
        }
    }

    fn download_item(
        &self,
        key: &Option<m3u8_rs::Key>,
        url: &str,
        path: &str,
        dir: &str,
        now: usize,
        total: usize,
        index: usize,
    ) -> Result<(), String> {
        log::info!("url = {url} path={path} {now}/{total}");
        if std::fs::exists(path).unwrap_or(false) {
            return Ok(());
        }
        match self.download_inner(url) {
            Ok(v) => {
                let v = self.decrypt(key, &v, dir)?;
                std::fs::write(path, &v[self.skip..]).map_err(|e| e.to_string())?;
            }
            Err((e, status)) => {
                if status == 404 && self.replace_not_found {
                    // 找到最近的下载成功的ts文件，就是上一个
                    for i in (0..index).rev() {
                        let p = Path::system(path).pop().join(format!("{i}.ts").as_str());
                        if std::fs::exists(p.to_string().as_str()).unwrap_or(false)
                            && std::fs::copy(p.to_string().as_str(), path).is_ok()
                        {
                            log::info!(
                                "file {path} not found, use the file [{}] replace it",
                                p.to_string()
                            );
                            break;
                        }
                    }
                } else {
                    return Err(format!(
                        "down file {url} fail, because the server return {}-{}",
                        e, status
                    ));
                }
            }
        }

        Ok(())
    }

    fn decrypt<'a>(
        &self,
        key: &Option<m3u8_rs::Key>,
        value: &[u8],
        dir: &str,
    ) -> Result<Vec<u8>, String> {
        if let Some(key) = key {
            match &key.method {
                m3u8_rs::KeyMethod::None => return Ok(value.to_vec()),
                m3u8_rs::KeyMethod::SampleAES => {
                    return Err("unsupport decrypt method SampleAES".to_string())
                }
                m3u8_rs::KeyMethod::Other(v) => {
                    return Err(format!("unsupport decrypt method {v}"))
                }
                m3u8_rs::KeyMethod::AES128 => {
                    log::info!("start decrypt");
                    if let Some(iv) = key
                        .iv
                        .as_ref()
                        .map(|f| f.replace("0x", ""))
                        .and_then(|f| hex_string_to_bytes(f.as_str()))
                    {
                        let v: Option<[u8; 16]> = key
                            .uri
                            .as_ref()
                            .map(|f| {
                                let mut hash = crypto::md5::Md5::new();
                                hash.input_str(f.as_str());

                                (format!("{dir}/{}.key", hash.result_str()), f.as_str())
                            })
                            .and_then(|(path, uri)| {
                                log::debug!("read the aes key from file {path}");
                                std::fs::read(path.as_str())
                                    .or_else(|_| {
                                        log::debug!("download the key file from uri = {uri}");
                                        // 读取uri
                                        self.download_inner(uri).map(|f| {
                                            let _ = std::fs::write(path.as_str(), f.as_slice());
                                            f.to_vec()
                                        })
                                    })
                                    .ok()
                            })
                            .and_then(|f| f.try_into().ok());

                        // 获取key
                        if let Some(v) = v {
                            return aes128_cbc_decrypt(
                                value,
                                &v,
                                &iv.try_into().map_err(|f| format!("decrypt e {:?}", f))?,
                            )
                            .map_err(|f| format!("decrypt fail {:?}", f));
                        }
                        return Err("decrypt fail, reason: get the aes key fail".to_string());
                    }
                    return Err("decrypt fail, reason: get the aes iv fail".to_string());
                }
            }
        }
        Ok(value.to_vec())
    }

    fn concat(&self, files: Arc<Vec<String>>, out: &str) -> Result<(), String> {
        if std::fs::exists(out).unwrap_or(false) {
            log::warn!("输出文件 {out} 已存在");
            return Ok(());
        }
        let not_download_file = files
            .iter()
            .map(|f| f.as_str())
            .filter(|f| !std::fs::exists(f).unwrap_or(false))
            .collect::<Vec<&str>>();
        // 校验所有文件都已下载成功
        if !not_download_file.is_empty() {
            log::warn!("文件未下载完成，不合并 [{}]", not_download_file.join(","));
            return Err("文件未下载完成，不合并".to_string());
        }

        log::info!("start ffmpeg, the out file = {out}");
        let c = std::process::Command::new(self.ffmpeg.as_str())
            .arg("-i")
            .arg(format!("concat:{}", files.join("|").as_str()).as_str())
            .arg("-y")
            .arg("-c")
            .arg("copy")
            .arg(out)
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("exec ffmpeg e ={}", e))?;
        let mut s = c
            .wait_with_output()
            .map_err(|e| format!("ffmpeg exec error = {e}"))?;

        let mut out = Vec::new();
        out.append(&mut s.stdout);
        out.append(&mut s.stderr);

        if !s.status.success() {
            return Err(format!(
                "ffmpge return e = {}, {}",
                s.status.code().unwrap_or(-1),
                String::from_utf8(out).map_err(|e| format!("get out e ={e}"))?
            ));
        }

        if self.clear {
            let dir = Path::system(files[0].as_str()).pop();
            if let Err(e) = std::fs::remove_dir_all(dir.to_string()) {
                log::warn!("删除ts文件失败 ={} {e}", dir.to_string());
            };
        }

        Ok(())
    }
}
#[derive(Clone)]
pub(crate) struct Path {
    /// 逐级路径
    paths: Vec<String>,
    /// home目录
    home: String,
    /// 分隔符
    sep: String,
}

impl Path {
    /// 基于操作系统解析路径
    pub fn system(path: &str) -> Self {
        #[cfg(target_os = "windows")]
        let sep = "\\";
        #[cfg(not(target_os = "windows"))]
        let sep = "/";
        // let v = path.split(sep);
        // for ele in v {
        //     paths.push(ele.to_string());
        // }

        Self {
            paths: Vec::new(),
            sep: sep.to_string(),
            home: String::new(),
        }
        .join(path)
    }

    pub fn join(&self, path: &str) -> Self {
        let mut s = self.clone();

        let v = path.split(s.sep.as_str());
        for ele in v {
            if ele == ".." {
                s.paths.pop();
            } else if ele == "." {
            } else if ele == "~" {
                // 因为在windows上正确处理 homedir 需要引入三方库，所以暂时就不实现了
                // s.paths.push(self.home.clone());
            } else {
                s.paths.push(ele.to_string());
            }
        }
        s
    }
    pub fn to_string(&self) -> String {
        // if self.is_absolute {
        //     format!("/{}",self.paths.join(&self.sep))
        // }else{
        self.paths.join(&self.sep)
        // }
    }
    pub fn pop(&self) -> Self {
        let mut s = self.clone();
        s.paths.pop();
        s
    }
}
#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;

    use crate::Path;

    #[test]
    fn test() {
        let mut p = Path::system("测试/2");
        p = p.join("..").join("out.mp4");
        println!("{}", p.to_string());

        let v =
            url::Url::parse("https://vpx05.myself-bbs.com/hls/eQ/oA/Ak/AgADeQoAAkpxIVU/index.m3u8")
                .unwrap();
        println!("{v}");
        println!("{}", v.join("").unwrap());
    }

    #[test]
    fn log() {
        // 消费

        let se = AtomicU32::new(3);
        println!("{}", se.fetch_sub(1, std::sync::atomic::Ordering::SeqCst));
        println!("{}", se.fetch_sub(1, std::sync::atomic::Ordering::SeqCst));

        // crossbeam::scope(|sc| {
        //     sc.spawn(|_| {
        //         println!("spawn1");
        //         std::thread::sleep(Duration::from_secs(20));
        //         println!("spawn2");
        //     });
        // })
        // .unwrap();

        // println!("scope over")
    }
}
