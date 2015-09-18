# snf-cdmi

`CDMI` `v1.0.2`/`v1.1` Server based on the Pithos+ storage backend


## Building
### With docker
Latest version `v0.4.4` features reproducible builds with Docker, which we assume you have already installed as a requirement (Docker version `1.5.0`, build `a8a31ef`).

Just run [`build.sh`](./build.sh) and after it has finished successfully, the target jar will be placed in `./target/` outside the container.

### Without docker
This is a maven project, so just run

```
$ mvn package
```

and you will one jar in `./target/`.

## Running
The produced JAR is self-contained, all library dependencies are provided build-in. 

In order to run the server in dev mode, you can use [`start-snf-cdmi`](./src/scripts/start-snf-cdmi).

For running in production environments, we support [`supervisord`](http://supervisord.org) and the corresponding start script is the slightly modified [`start-snf-cdmi.supervisord`](./src/scripts/start-snf-cdmi.supervisord). The relevant configuration for `supervisord` is [snf-cdmi.conf](./src/scripts/etc/supervisor/conf.d/snf-cdmi.conf), which should be placed under `/etc/supervisor/conf.d/` in the target machine.

The server will also need the respective SSL certificate and key files. For these, we assume the names `cdmi-cert.pem` and `cdmi-key.pem`.

All files (jar, start script, SSL-related) are expected by convention in the same folder; this is pre-configured to be `/root/snf-cdmi`, as is evident from the `supervisord` configuration file. The server produces rolling log files in the same folder.