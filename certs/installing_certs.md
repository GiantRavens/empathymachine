
# Installing Certs

## On macOS

In your system keychain, add the empathy-root.pem file to the System keychain. Then, double-click on the empathy-root.pem file and set the trust to "Always Trust".

In Network Settings (i.e. WiFi) click settings and add the DNS server `127.0.0.1` to blackhole DNS requests, and set your http/https proxy to `127.0.0.1:8080`.

## On Linux (Debian)

After dumping your certs with `empathymachine dump-ca > empathy-root.pem`, you can install them with:

```bash
sudo cp empathy-root.pem /usr/local/share/ca-certificates/empathymachine.crt
sudo update-ca-certificates
```
