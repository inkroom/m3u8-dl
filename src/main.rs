use std::{ffi::CString, sync::Arc};

use clap::Parser;
use m3u8_rs::{MediaPlaylist, Playlist};

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
    let opt = Opt::parse();

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

                match run(opt) {
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
    match run(opt) {
        Ok(_) => {}
        Err(e) => {
            log::error!("{e}");
            std::process::exit(101);
        }
    }
}

fn run(opt: Opt) -> Result<(), String> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(uid) = opt.uid {
        unsafe {
            let _ = libc::setuid(uid);
            let _ = libc::setgid(uid);
        }
    }
    if !opt.name.as_str().ends_with(".mp4") && !opt.name.as_str().ends_with(".mkv") {
        return Err("name 必须有文件格式".to_string());
    }

    let out = format!("{}/{}", opt.dir, opt.name);
    if std::fs::exists(out.as_str()).unwrap_or(false) {
        log::info!("the out file exists = [{out}] ");
        return Ok(());
    }

    let ts = get_m3u8_ts_url(opt.url.as_str(), "", &opt)?;

    download(
        ts.iter().map(|f| f).collect::<Vec<&String>>().as_slice(),
        format!(
            "{}/{}",
            opt.dir,
            opt.name.replace(".mp4", "").replace(".mkv", "")
        )
        .as_str(),
        out.as_str(),
        &opt,
    )?;

    log::info!("下载完成 {} ", opt.url);
    Ok(())
}

fn get_m3u8_ts_url(url: &str, uri: &str, opt: &Opt) -> Result<Vec<String>, String> {
    let m3u8_url = url::Url::parse(url)
        .and_then(|f| f.join(uri))
        .map_err(|e| format!("m3u8 url not valid {}", e))?;
    log::info!("downloading m3u8 {}", m3u8_url);

    let resp = download_inner(m3u8_url.as_str(), opt)?;
    if resp.status_code == 200 {
        match m3u8_rs::parse_playlist_res(resp.as_bytes()) {
            Ok(Playlist::MasterPlaylist(m)) => {
                let mut v = Vec::new();
                for ele in &m.variants {
                    v.append(&mut get_m3u8_ts_url(
                        m3u8_url.as_str(),
                        ele.uri.as_str(),
                        opt,
                    )?);
                }
                return Ok(v);
            }
            Ok(Playlist::MediaPlaylist(me)) => {
                return Ok(me
                    .segments
                    .iter()
                    .map(|f| get_real_url(m3u8_url.as_str(), f.uri.as_str()))
                    .filter(|f| f.is_ok())
                    .map(|f| f.unwrap().to_string())
                    .collect::<Vec<String>>());
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Err(format!("resp error {} {}", resp.status_code, m3u8_url))
}

fn download(list: &[&String], dir: &str, out: &str, opt: &Opt) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create dir = {}", e.to_string()))?;

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
        for i in 0..opt.thread {
            let s = Arc::clone(&thread_queue);
            sc.spawn(move |_| {
                while let Some((url, file)) = s.pop() {
                    log::debug!("thread {i} {url}",);
                    let now = segment_count - s.len();
                    for i in 0..opt.retry {
                        if let Err(e) =
                            download_item(url.as_str(), file.as_str(), opt, now, segment_count)
                        {
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

    concat(
        list.iter()
            .enumerate()
            .map(|(index, _)| format!("{dir}/{index}.ts"))
            .collect::<Vec<String>>(),
        out,
        opt,
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

fn download_inner(url: &str, opt: &Opt) -> Result<minreq::Response, String> {
    let mut req = minreq::get(url);
    if !opt.no_proxy {
        if let Some(proxy) = &opt.proxy {
            req = req
                .with_proxy(minreq::Proxy::new(proxy).map_err(|e| format!("proxy not valid {e}"))?);
        } else if let Some(proxy) = get_env_proxy(url) {
            log::info!("use proxy ={proxy}");
            req = req
                .with_proxy(minreq::Proxy::new(proxy).map_err(|e| format!("proxy not valid {e}"))?);
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

fn download_item(url: &str, path: &str, opt: &Opt, now: usize, total: usize) -> Result<(), String> {
    if std::fs::exists(path).unwrap_or(false) {
        return Ok(());
    }

    let resp = download_inner(url, opt)?;
    if resp.status_code == 200 {
        if let Some(len) = resp.headers.get("content-length") {
            let v = resp.as_bytes();
            if v.len() == len.parse::<usize>().map_err(|e| e.to_string())? {
                log::info!("url = {url} path={path} {now}/{total}");
                std::fs::write(path, &v[opt.skip..]).map_err(|e| e.to_string())?;
            } else {
                return Err("len not eq".to_string());
            }
        } else {
            return Err("no cotent-length".to_string());
        }
    } else if resp.status_code == 404 && opt.replace_not_found {
        // 找到最近的下载成功的ts文件，就是上一个
        for i in (0..now - 1).rev() {
            let p = Path::system(path).pop().join(format!("{i}.ts").as_str());
            if std::fs::exists(p.to_string().as_str()).unwrap_or(false) {
                if let Ok(_) = std::fs::copy(p.to_string().as_str(), path) {
                    log::info!(
                        "file {path} not found, use the file [{}] replace it",
                        p.to_string()
                    );
                };
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

fn concat(files: Vec<String>, out: &str, opt: &Opt) -> Result<(), String> {
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
    let c = std::process::Command::new(opt.ffmpeg.as_str())
        .arg("-i")
        .arg(format!("concat:{}", files.join("|").as_str()).as_str())
        .arg("-y")
        .arg("-c")
        .arg("copy")
        .arg(out)
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("exec ffmpeg e ={}", e.to_string()))?;
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

    if opt.clear {
        let dir = Path::system(files[0].as_str()).pop();
        if let Err(e) = std::fs::remove_dir_all(dir.to_string()) {
            log::warn!("删除ts文件失败 ={} {e}", dir.to_string());
        };
    }

    Ok(())
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
