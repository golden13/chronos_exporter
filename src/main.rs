extern crate prometheus_exporter_base;
extern crate clap;
extern crate log;
extern crate env_logger;
extern crate sysinfo;
extern crate gethostname;
extern crate config;

use clap::{crate_authors, crate_name, crate_version, Arg};
use log::{info, trace};
use prometheus_exporter_base::{render_prometheus, MetricType, PrometheusMetric};
use std::env;
use std::net::{SocketAddr};
use std::sync::Arc;
use std::str::from_utf8;
use sysinfo::{SystemExt, DiskExt, DiskType};


#[macro_use]
extern crate serde;
extern crate serde_derive;
extern crate serde_json;
extern crate reqwest;
use reqwest::Client;
use config::Config;
use std::error::Error;

fn disk_type_to_str(dtype: &DiskType) -> &str {
    match *dtype {
        DiskType::HDD => "HDD",
        DiskType::SSD => "SSD",
        DiskType::Unknown(_any) => "Unknown"
    }
}


#[derive(Debug, Clone, Default)]
struct MyOptions<'a> {
    targets:Vec<&'a str>
}

#[derive(Serialize,Deserialize,Debug)]
struct HttpAuthorization {
    username: String,
    password: String
}

#[derive(Serialize,Deserialize,Debug)]
struct OneJob {
    name: String,
    status: String,
    state: String,
    schedule: String,
    disabled: Option<bool>
}

#[derive(Serialize,Deserialize,Debug)]
struct Jobs {
    jobs: Vec<OneJob>
}

fn call_rest_api(settings: Arc<Config>) -> Jobs {
    //let auth = call_rest_api_auth().unwrap();
    let username = settings.get("username");
    let password = settings.get("password");

    let auth = HttpAuthorization {
        username: username.unwrap(),
        password: password.unwrap(),
    };

    let host = settings.get("chronos_host");
    let path= settings.get("get_job_status_path");
    let data = call_rest_api_info(host.unwrap(), path.unwrap(), auth);
    let data = match data {
        Ok(data) => data,
        Err(error) => {panic!("Error in request: {:?}", handler(error))},
    };
    return data;
}

fn handler(e: reqwest::Error) {

    println!("Error: {:?}", e.to_string());
    if e.is_http() {
        match e.url() {
            None => println!("ERROR: No Url given"),
            Some(url) => println!("ERROR: Problem making request to: {}", url),
        }
    }
    // Inspect the internal error and output it
    if e.is_serialization() {
        let serde_error = match e.get_ref() {
            None => return,
            Some(err) => err,
        };
        println!("ERROR: Problem parsing information {}", serde_error);
    }
    if e.is_redirect() {
        println!("ERROR: Server redirecting too many times or making loop");
    }
}

fn call_rest_api_info(host: String, path: String, auth: HttpAuthorization) -> Result<Jobs, reqwest::Error> {
    let request_url = format!("{}{}", host, path);
    println!("Sending Request to: {:?}", request_url);

    let mut response = Client::new()
        .get(request_url.as_str())
        .basic_auth(auth.username, Some(auth.password))
        //.header("Authorization", auth.token)
        .send()?;

    let data: Jobs = response.json()?;
    println!("Response status: {:?}", response.status());
    println!("Response body: {:?}", data);
    Ok (data)
}


fn load_config(name: &str) -> Result<Config, Box<dyn Error>> {
    let mut settings = Config::default();

    settings.merge(config::File::with_name(name)).unwrap();

    Ok(settings)
}

fn main() {
    let matches = clap::App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .help("config file name")
                .default_value("config.yml")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .help("exporter port")
                .default_value("9104")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .help("verbose logging")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("listen")
                .short("l")
                .help("hostname")
                .default_value("0.0.0.0")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("chronos_host")
                .short("h")
                .help("chronos server URL with trailing slash, ex.: http://chronos.host.com/")
                //.default_value("http://chronos.host.com/")
                .takes_value(true)
        )
        .get_matches();

    if matches.is_present("verbose") {
        env::set_var(
            "RUST_LOG",
            format!("folder_size=trace,{}=trace", crate_name!()),
        );
    } else {
        env::set_var(
            "RUST_LOG",
            format!("folder_size=info,{}=info", crate_name!()),
        );
    }
    env_logger::init();

    info!("Using matches: {:?}", matches);

    let config_filename = matches.value_of("config").unwrap_or("config.yml");
    println!("Using config file: {}", config_filename);

    // reading config file
    let options = load_config(config_filename).unwrap();

    let bind = matches.value_of("port").unwrap();
    let bind = u16::from_str_radix(&bind, 10).expect("ERROR: Port must be a valid number");
    let host =  format!("{}:{}", matches.value_of("listen").unwrap(), bind);

    let addr: SocketAddr = host
        .parse()
        .expect("ERROR: Unable to parse socket address");

    info!("Starting exporter on {} ...", addr);

    render_prometheus(addr, options, |request, options| {
        async move {
            let hostname = gethostname::gethostname();

            trace!(
                "Request: {:?}, Options: {:?})",
                request,
                options
            );

            println!("Calling Chronos REST API...");
            let data = call_rest_api(options);

            //let metric1 = PrometheusMetric::new("chronos_jobs", MetricType::Gauge, "");
            let mut s = String::new();//metric1.render_header();

            //let skip_disabled = options2.get("skip_disabled_jobs").unwrap_or(1);

            for elem in data.jobs.iter() {
                let s_slice: &OneJob = &elem;
                //let status_str = s_slice.status.as_str();

                // only enabled jobs
                if !s_slice.disabled.unwrap() { // && skip_disabled == 1
                    //let full_name = format!("{}{}", "chronos_job_", status_str);
                    let full_name = "chronos_job_status";
                    let job_metric = PrometheusMetric::new(full_name, MetricType::Gauge, "Values: 0 - failure, 1 - success, 2 - other");

                    let mut attributes = Vec::new();
                    attributes.push(("name", s_slice.name.as_str()));
                    attributes.push(("status", s_slice.status.as_str()));
                    attributes.push(("state", s_slice.state.as_str()));
                    attributes.push(("schedule", s_slice.schedule.as_str()));
                    attributes.push(("host", hostname.to_str().unwrap()));
                    //attributes.push(("disabled", s_slice.disabled.as_str()));

                    let mut status_int = 1;

                    if s_slice.status == "success" {
                        status_int = 1;
                    } else if s_slice.status == "failure" {
                        status_int = 0;
                    } else {
                        status_int = 2;
                    }
                    s.push_str(&job_metric.render_header());
                    s.push_str(&job_metric.render_sample(Some(&attributes), status_int));
                }
            }

            // Get system info
            let mut system = sysinfo::System::new();
            system.refresh_all();
            let mut attributes = Vec::new();
            attributes.push(("host", hostname.to_str().unwrap()));

            // mem_swap_total
            let pmetric_mem_swap_total = PrometheusMetric::new("mem_swap_total", MetricType::Gauge, "mem_swap_total collected metric");
            s.push_str(&pmetric_mem_swap_total.render_header());
            s.push_str(&pmetric_mem_swap_total.render_sample(Some(&attributes), system.get_total_swap()));

            // mem_total
            let pmetric_mem_total = PrometheusMetric::new("mem_total", MetricType::Gauge, "mem_total collected metric");
            s.push_str(&pmetric_mem_total.render_header());
            s.push_str(&pmetric_mem_total.render_sample(Some(&attributes), system.get_total_memory()));

            // mem_used
            let pmetric_mem_used = PrometheusMetric::new("mem_used", MetricType::Gauge, "mem_used collected metric");
            s.push_str(&pmetric_mem_used.render_header());
            s.push_str(&pmetric_mem_used.render_sample(Some(&attributes), system.get_used_memory()));

            // mem_swap_used
            // INFO: Telegraf doesn't have this metric, only mem_swap_free.
            let pmetric_mem_swap_used = PrometheusMetric::new("mem_swap_used", MetricType::Gauge, "mem_swap_used collected metric");
            s.push_str(&pmetric_mem_swap_used.render_header());
            s.push_str(&pmetric_mem_swap_used.render_sample(Some(&attributes), system.get_used_swap()));

            // Disks information
            let pmetric_disk_free = PrometheusMetric::new("disk_free", MetricType::Gauge, "disk_free collected metric");
            s.push_str(&pmetric_disk_free.render_header());

            let pmetric_disk_total = PrometheusMetric::new("disk_total", MetricType::Gauge, "disk_total collected metric");
            let mut s2 = pmetric_disk_total.render_header();

            //system.refresh_disk_list();
            for disk in system.get_disks() {
                //info!("{:?}", disk);
                let mut attributes2 = Vec::new();
                let path = disk.get_name().to_str().unwrap();
                attributes2.push(("device", path));

                attributes2.push(("host", hostname.to_str().unwrap()));

                let fstype = disk.get_file_system();
                attributes2.push(("fstype", from_utf8(fstype).unwrap()));

                attributes2.push(("path", disk.get_mount_point().to_str().unwrap()));

                let dtype_enum = &disk.get_type();
                let dtype = disk_type_to_str(dtype_enum);

                attributes2.push(("type", dtype));

                // TODO: mode="rw", host="xxx"
                s.push_str(&pmetric_disk_free.render_sample(Some(&attributes2), disk.get_available_space()));
                s2.push_str(&pmetric_disk_total.render_sample(Some(&attributes2), disk.get_total_space()));
            }

            s.push_str(&s2);

            Ok(s)
        }
    });

}
