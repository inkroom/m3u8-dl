use std::{ffi::CString, sync::Arc};

use clap::Parser;
use crypto::digest::Digest;
use m3u8_rs::Playlist;

#[derive(Parser, Debug)]
struct Opt {
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
        long_help = "当ts返回404时，使用最近的已下载的ts替换",
        default_value = "false"
    )]
    replace_not_found: bool,
    #[arg(short, long, default_value = "false", help = "输出更多日志")]
    verbose: bool,
}

fn main() {
    let mut opt = Opt::parse();

    // println!("{:?}", opt);
    let s = simple_log::LogConfigBuilder::builder()
        .level(if opt.verbose {
            "debug,rustls=info"
        } else {
            "info"
        })
        .unwrap()
        .time_format("%Y-%m-%d %H:%M:%S.%f")
        .output_console();

    if let Some(log) = &opt.log {
        simple_log::new(s.path(log).output_file().build()).expect("log init error");
    } else {
        simple_log::new(s.build()).expect("log init error");
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

impl Opt {
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

        log::info!("下载完成 {} ", self.url);
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

        let resp = self.download_inner(m3u8_url.as_str())?;
        if resp.status_code == 200 {
            match m3u8_rs::parse_playlist_res(resp.as_bytes()) {
                Ok(Playlist::MasterPlaylist(m)) => {
                    let mut v = Vec::new();
                    for ele in &m.variants {
                        v.append(&mut self.get_m3u8_ts_url(m3u8_url.as_str(), ele.uri.as_str())?);
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
        Err(format!("resp error {} {}", resp.status_code, m3u8_url))
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

    fn download_inner(&self, url: &str) -> Result<minreq::Response, String> {
        let mut req = minreq::get(url);
        if !self.no_proxy {
            if let Some(proxy) = &self.proxy {
                req = req.with_proxy(
                    minreq::Proxy::new(proxy).map_err(|e| format!("proxy not valid {e}"))?,
                );
            } else if let Some(proxy) = Self::get_env_proxy(url) {
                log::info!("use proxy ={proxy}");
                req = req.with_proxy(
                    minreq::Proxy::new(proxy).map_err(|e| format!("proxy not valid {e}"))?,
                );
            }
        }
        req.send().map_err(|e| e.to_string())
    }

    fn get_env_proxy(url: &str) -> Option<String> {
        if url.starts_with("https") {
            std::env::var("HTTPS_PROXY")
                .or_else(|_| std::env::var("https_proxy"))
                .or_else(|_| std::env::var("ALL_PROXY"))
                .or_else(|_| std::env::var("all_proxy"))
        } else {
            std::env::var("HTTP_PROXY")
                .or_else(|_| std::env::var("http_proxy"))
                .or_else(|_| std::env::var("ALL_PROXY"))
                .or_else(|_| std::env::var("all_proxy"))
        }
        .ok()
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

        let resp = self.download_inner(url)?;
        if resp.status_code == 200 {
            if let Some(len) = resp.headers.get("content-length") {
                let v = resp.as_bytes();
                if v.len() == len.parse::<usize>().map_err(|e| e.to_string())? {
                    log::info!("url = {url} path={path} {now}/{total}");
                    let v = self.decrypt(key, v, dir)?;
                    std::fs::write(path, &v[self.skip..]).map_err(|e| e.to_string())?;
                } else {
                    return Err("len not eq".to_string());
                }
            } else {
                return Err("no cotent-length".to_string());
            }
        } else if resp.status_code == 404 && self.replace_not_found {
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
                "down file {url} fail, because the server return {}",
                resp.status_code
            ));
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
                                            let _ = std::fs::write(path.as_str(), f.as_bytes());
                                            f.as_bytes().to_vec()
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
}
