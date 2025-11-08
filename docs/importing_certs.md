# Importing the EmpathyMachine Root Certificate

EmpathyMachine generates a private certificate authority (CA) the first time it
runs. Clients that should trust the proxy must import this root certificate so
that the TLS interception layer is transparent. The steps below explain how to
export the CA and add it to trust stores on macOS and Linux.

## 1. Export the CA

From the EmpathyMachine project directory, dump the root certificate to a PEM
file:

```bash
cargo run -- --dump-ca > empathy-root.pem
```

Distribute `empathy-root.pem` to any client that will use the proxy. Keep it in a
secure location because anyone with this certificate and the corresponding
private key could impersonate your proxy.

## 2. macOS

1. Open **Keychain Access**.
2. Select the **System** keychain in the sidebar.
3. Choose **File → Import Items…** and select `empathy-root.pem`.
4. After the import, double-click the new "EmpathyMachine Root" (or similarly
   named) certificate.
5. Expand **Trust** and set **When using this certificate** to **Always Trust**.
6. Close the window and provide administrator credentials when prompted.

All macOS apps that rely on the system trust store (Safari, Chrome, curl, etc.)
will now accept certificates issued by EmpathyMachine.

## 3. Linux

Different distributions use different trust stores. The steps below cover the
most common families. Always run them as root or with `sudo`.

### Debian / Ubuntu / Linux Mint

```bash
sudo cp empathy-root.pem /usr/local/share/ca-certificates/empathymachine.crt
sudo update-ca-certificates
```

### Fedora / RHEL / CentOS / Alma / Rocky

```bash
sudo cp empathy-root.pem /etc/pki/ca-trust/source/anchors/empathymachine.pem
sudo update-ca-trust
```

### Arch / Manjaro / EndeavourOS

```bash
sudo cp empathy-root.pem /usr/local/share/ca-certificates/empathymachine.crt
sudo trust extract-compat
```

### Firefox (all distributions)

Firefox maintains its own NSS database when running in standalone mode. If your
browser does not automatically pick up the system trust store:

1. Open **Settings → Privacy & Security**.
2. Scroll to **Certificates** and click **View Certificates**.
3. Under the **Authorities** tab, click **Import…**, choose `empathy-root.pem`,
   and enable "Trust this CA to identify websites".

### Chromium-Based Browsers

On most Linux distributions Chromium, Google Chrome, and Brave use the system
trust store. After updating the system certificates, restart the browser. If you
start the browser with the `--user-data-dir` flag, verify that `--use-system-
certs` is enabled.

## 4. Verify Installation

After importing the certificate, visit an HTTPS site through EmpathyMachine. The
browser should no longer warn about invalid certificates. You can also inspect
the connection details and confirm that the issuing authority matches the name
of the EmpathyMachine root.

If the browser still complains, flush its certificate cache or restart the
application to ensure it loads the updated trust store.
