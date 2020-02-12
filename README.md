# Prometheus Chronos Jobs Exporter
Prometheus exporter for [Chronos](https://github.com/mesos/chronos) jobs statuses.

Uses [Chronos](https://github.com/mesos/chronos) API to get job list with statuses
 
*Written in [Rust](https://github.com/rust-lang/rust)*

*Built using: [Prometheus exporter base](https://github.com/MindFlavor/prometheus_exporter_base)*

# Configuration
*config.yml*
```yaml
# Basic Auth
username: "username"
password: "password"

# Chronos server URL with trailing slash
chronos_host: "http://chronos.myserver.com/"

# Get Job Status API path
get_job_status_path: "v1/scheduler/jobs/summary"

# Return information only for enabled jobs
skip_disabled_jobs: 1
```

# Run
```chronos_exporter -p 9104 -h 127.0.0.1 ```

Using custom config:
```chronos_exporter -c conf/my_config.yml ```

# Command line arguments
```cmd
-c [config] - config file name
-p [port] - port number, default 9104
-l [listen] - hostname, default 0.0.0.0
-v [verbouse] - verbose 
-h [chtrono_host] - Chronos server URL with trailing slash
```

# Compile binaries 
**NOTE:** Use Rust nightly version

```cargo +nightly build --release```

# Output example
```promql
# HELP chronos_job_status Values: 0 - failure, 1 - success, 2 - other
# TYPE chronos_job_status gauge
chronos_job_status{name="UpdaterJob",status="success",state="idle",schedule="R/2020-02-04T09:35:00.000-04:00/PT5M",host="ip-1-1-0-1"} 1
# HELP chronos_job_status Values: 0 - failure, 1 - success, 2 - other
# TYPE chronos_job_status gauge
chronos_job_status{name="RunSkynet",status="success",state="idle",schedule="R/2020-02-04T14:08:04.000Z/PT60M",host="ip-1-3-0-1"} 1
# HELP chronos_job_status Values: 0 - failure, 1 - success, 2 - other
# TYPE chronos_job_status gauge
chronos_job_status{name="KillAllHumans",status="success",state="idle",schedule="R/2020-02-04T09:35:00.000-04:00/PT5M",host="ip-1-3-0-2"} 1
```

