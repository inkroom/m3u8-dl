use std::fmt::Debug;
use std::time::SystemTime;
use std::{ffi::CString, sync::Arc};

use clap::Parser;
use crypto::digest::Digest;
use log::LevelFilter;

use m3u8_rs::Playlist;

#[derive(Parser)]
pub struct Opt {
    #[arg(short, long = "url", help = "m3u8地址")]
    url: String,
    #[arg(short, long = "dir", help = "输出文件夹")]
    dir: String,
    #[arg(short, long, help = "输出文件名，必须以mp4或者mkv结尾")]
    name: String,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[arg(long, help = "使用指定uid运行程序(unavailable for window)")]
    uid: Option<u32>,
    #[arg(short, long, default_value = "4", help = "线程数量")]
    thread: u32,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(
        long,
        help = "后台运行(unavailable for windows)",
        default_value = "false"
    )]
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

    #[arg(skip)]
    client: Option<Box<dyn HttpClient + Send + Sync>>,
    #[arg(skip)]
    begin: Option<std::time::SystemTime>,
}

impl Debug for Opt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opt")
            .field("url", &self.url.as_str())
            .field("dir", &self.dir)
            .field("name", &self.name)
            .field("log", &self.log.as_ref().map(|f| f.as_str()).unwrap_or(""))
            .field("thread", &self.thread)
            .field("skip", &self.skip)
            .field("retry", &self.retry)
            .field("ffmpeg", &self.ffmpeg)
            .field(
                "proxy",
                &self.proxy.as_ref().map(|f| f.as_str()).unwrap_or(""),
            )
            .field(
                "no_proxy",
                &self.proxy.as_ref().map(|f| f.as_str()).unwrap_or(""),
            )
            .field("verbose", &self.verbose)
            .finish()
    }
}

pub trait HttpClient: Send {
    fn init(opt: &Opt) -> Result<Self, String>
    where
        Self: Sized;

    fn get(&self, url: &str) -> Result<Vec<u8>, (String, u16)>;
}

#[cfg(feature = "ureq")]
mod ureqclient {
    use crate::{HttpClient, Opt};

    pub(crate) struct UReqClient {
        inner: ureq::Agent,
    }

    impl HttpClient for UReqClient {
        fn init(opt: &Opt) -> Result<Self, std::string::String> {
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
        fn init(opt: &crate::Opt) -> Result<Self, String>
        where
            Self: Sized,
        {
            let mut c = reqwest::blocking::Client::builder();
            if !opt.no_proxy {
                if let Some(proxy) = &opt.proxy {
                    log::debug!("use proxy = {}", proxy);
                    c = c.no_proxy().proxy(
                        reqwest::Proxy::all(proxy)
                            .expect(format!("unvalid proxy = {}", proxy).as_str()),
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

fn main() {
    let mut opt = Opt::parse();

    if let Err(e) = opt.init() {
        log::error!("{e}");
        std::process::exit(101);
    }
    log::info!("参数={:?}", opt);

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if opt.daemon {
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
    match opt.run() {
        Ok(_) => {}
        Err(e) => {
            log::error!("{e}");
            std::process::exit(101);
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

impl std::io::Write for Opt {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        todo!()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!()
    }
}
mod custom_log {
    use crate::Opt;
    use env_logger::fmt::Formatter;
    use std::io::Write;
    /// 时间戳转换，从1970年开始
    pub(crate) fn time_display(value: u64) -> String {
        do_time_display(value, 1970)
    }

    /// 时间戳转换，支持从不同年份开始计算
    pub(crate) fn do_time_display(value: u64, start_year: u64) -> String {
        // 先粗略定位到哪一年
        // 以 365 来计算，年通常只会相比正确值更晚，剩下的秒数也就更多，并且有可能出现需要往前一年的情况

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

        return format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            year,
            month,
            time,
            hour + 8,
            min,
            sec
        );
    }
    //
    // 判断是否是闰年
    //
    fn is_leap(year: u64) -> bool {
        return year % 4 == 0 && ((year % 100) != 0 || year % 400 == 0);
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
        pub fn new(opt: &Opt) -> Self {
            Writer {
                console: std::io::stdout(),
                fs: if let Some(f) = &opt.log {
                    Some(
                        std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(f.as_str())
                            .unwrap(),
                    )
                } else {
                    None
                },
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
    pub(crate) fn init(opt: &Opt) -> Result<(), String> {
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
    // fn log(&self) {
    //     let pattern = "{d(%Y-%m-%d %H:%M:%S)} : {m}{n}";

    //     let mut s = log4rs::Config::builder()
    //         .appender(
    //             log4rs::config::Appender::builder().build(
    //                 "stdout",
    //                 Box::new(
    //                     log4rs::append::console::ConsoleAppender::builder()
    //                         .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
    //                             pattern,
    //                         )))
    //                         .build(),
    //                 ),
    //             ),
    //         )
    //         .logger(Logger::builder().build("rustls", LevelFilter::Off));

    //     if let Some(log) = &self.log {
    //         s = s.appender(
    //             log4rs::config::Appender::builder().build(
    //                 "file",
    //                 Box::new(
    //                     log4rs::append::file::FileAppender::builder()
    //                         .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
    //                             pattern,
    //                         )))
    //                         .build(log)
    //                         .unwrap(),
    //                 ),
    //             ),
    //         );
    //     }
    //     log4rs::init_config(
    //         s.build(
    //             log4rs::config::Root::builder()
    //                 .appender("stdout")
    //                 .appender("file")
    //                 .build(if self.verbose {
    //                     LevelFilter::Debug
    //                 } else {
    //                     LevelFilter::Info
    //                 }),
    //         )
    //         .unwrap(),
    //     )
    //     .unwrap();
    // }

    fn init(&mut self) -> Result<(), String> {
        // self.log();
        custom_log::init(self)?;

        #[cfg(feature = "ureq")]
        {
            self.client = Some(Box::new(ureqclient::UReqClient::init(&self)?));
        }
        #[cfg(feature = "west")]
        {
            self.client = Some(Box::new(reqwestclient::ReqWestClient::init(&self)?));
        }

        self.begin = Some(SystemTime::now());
        Ok(())
    }

    fn run(&mut self) -> Result<(), String> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(uid) = self.uid {
            unsafe {
                let _ = libc::setuid(uid);
                let _ = libc::setgid(uid);
            }
        }
        if !self.name.as_str().ends_with(".mp4") && !self.name.as_str().ends_with(".mkv") {
            return Err("name 必须有文件格式".to_string());
        }

        let out = format!("{}/{}", self.dir, self.name);
        if std::fs::exists(out.as_str()).unwrap_or(false) {
            log::info!("the out file exists = [{out}] ");
            return Ok(());
        }

        let ts = self.get_m3u8_ts_url(self.url.as_str(), "")?;

        self.download(
            ts,
            format!(
                "{}/{}",
                self.dir,
                self.name.replace(".mp4", "").replace(".mkv", "")
            )
            .as_str(),
            out.as_str(),
        )?;

        log::info!(
            "下载完成 {} 耗时 ={}秒",
            self.url,
            SystemTime::now()
                .duration_since(self.begin.clone().unwrap())
                .unwrap()
                .as_secs()
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
                        return Ok(v);
                    }
                    Ok(Playlist::MediaPlaylist(me)) => {
                        // 如果有需要解密的key，这个key只会出现在第0个ts上，但是每个ts都需要用

                        let key = me.segments[0].key.clone();

                        return Ok(me
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
                            .collect::<Vec<(Option<m3u8_rs::Key>, String)>>());
                    }
                    Err(e) => return Err(e.to_string()),
                }
            }
            Err((e, status)) => Err(format!("resp error {} {} {e}", status, m3u8_url)),
        }
    }

    fn download(
        &self,
        list: Vec<(Option<m3u8_rs::Key>, String)>,
        dir: &str,
        out: &str,
    ) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create dir = {}", e))?;

        let queue = std::sync::Arc::new(crossbeam::queue::SegQueue::new());
        let segment_count = list.len();
        for (index, ele) in list.iter().enumerate() {
            // ele.uri
            // println!("{}", ele.uri);
            // let v = get_real_url(m3u8, ele.as_str())?;
            let v = ele;
            queue.push((v.clone(), format!("{dir}/{}.ts", index)));
        }
        let thread_queue = Arc::clone(&queue);
        // 消费
        crossbeam::scope(|sc| {
            for i in 0..self.thread {
                let s = Arc::clone(&thread_queue);
                sc.spawn(move |_| {
                    while let Some(((key, url), file)) = s.pop() {
                        log::debug!("thread {i} {url}",);
                        let now = segment_count - s.len();
                        for i in 0..self.retry {
                            if let Err(e) = self.download_item(
                                &key,
                                url.as_str(),
                                file.as_str(),
                                dir,
                                now,
                                segment_count,
                            ) {
                                log::error!(
                                "download file fail ={url}, reason =[{e}] after retry {i} count"
                            );
                            } else {
                                // 成功
                                break;
                            }
                        }
                    }
                });
            }
        })
        .unwrap();

        // 等待
        loop {
            if queue.is_empty() {
                log::info!("完成");
                break;
            }
        }

        self.concat(
            list.iter()
                .enumerate()
                .map(|(index, _)| format!("{dir}/{index}.ts"))
                .collect::<Vec<String>>(),
            out,
        )
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
    ) -> Result<(), String> {
        if std::fs::exists(path).unwrap_or(false) {
            return Ok(());
        }
        match self.download_inner(url) {
            Ok(v) => {
                log::info!("url = {url} path={path} {now}/{total}");
                let v = self.decrypt(key, &v, dir)?;
                std::fs::write(path, &v[self.skip..]).map_err(|e| e.to_string())?;
            }
            Err((e, status)) => {
                if status == 404 && self.replace_not_found {
                    // 找到最近的下载成功的ts文件，就是上一个
                    for i in (0..now - 1).rev() {
                        let p = Path::system(path).pop().join(format!("{i}.ts").as_str());
                        if std::fs::exists(p.to_string().as_str()).unwrap_or(false)
                            && std::fs::copy(p.to_string().as_str(), path).is_ok()
                        {
                            log::info!(
                                "file {path} not found, use the file [{}] replace it",
                                p.to_string()
                            );
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

    fn concat(&self, files: Vec<String>, out: &str) -> Result<(), String> {
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
        let pattern = "{d(%Y-%m-%d %H:%M:%S)} : {m}{n}";
        let mut s = log4rs::Config::builder()
            .appender(
                log4rs::config::Appender::builder().build(
                    "stdout",
                    Box::new(
                        log4rs::append::console::ConsoleAppender::builder()
                            .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
                                pattern,
                            )))
                            .build(),
                    ),
                ),
            )
            .logger(log4rs::config::Logger::builder().build("rustls", log::LevelFilter::Off));

        // // println!("{:?}", opt);
        // let s = simple_log::LogConfigBuilder::builder()
        //     .level(if opt.verbose {
        //         "debug,rustls=info"
        //     } else {
        //         "info"
        //     })
        //     .unwrap()
        //     .time_format("%Y-%m-%d %H:%M:%S")
        //     .output_console();

        // if let Some(log) = &opt.log {
        s = s.appender(
            log4rs::config::Appender::builder().build(
                "file",
                Box::new(
                    log4rs::append::file::FileAppender::builder()
                        .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
                            pattern,
                        )))
                        .build("55.log")
                        .unwrap(),
                ),
            ),
        );
        // }

        log4rs::init_config(
            s.build(
                log4rs::config::Root::builder()
                    .appender("stdout")
                    .appender("file")
                    .build(log::LevelFilter::Debug),
            )
            .unwrap(),
        )
        .unwrap();

        log::info!("参数=");
    }
}
