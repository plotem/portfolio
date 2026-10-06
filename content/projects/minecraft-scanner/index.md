+++
date = '2026-08-19'
draft = true
title = 'Minecraft Scanner'
+++
# Building a Minecraft Server Scanner

This project started with a pretty simple question:

**How did some random person find my Minecraft server?**

## The Incident

This summer, I was playing Minecraft (java edition) with some friends on a server I was hosting from my desktop PC. Since I couldn't port-forward on my network, I was using [playit.gg](https://playit.gg/) to create a tunnel to the server. (My internet connection was provided through a 4G LTE modem, which made port forwarding impossible.)

The server wasn't running 24/7 either. I'd only turn it on when we were playing.

Because of that, I didn't initially bother setting up a whitelist. The server was supposed to be private and I hadn't shared the address outside our discord server.

Then one day, while we were playing, a completely random person joined.

They immediately started flying around the server, stealing stuff from chests and breaking glass.

None of us had shared the address publicly, so we were all pretty confused.

The obvious question became:

> **How did they find us?**

That question sent me down a bit of a rabbit hole and onto making this (somewhat scuffed) minecraft server scanner

---

## Falling Down the Rabbit Hole

While trying to figure out how someone could discover a Minecraft server that wasn't publicly advertised, I came across a YouTube series by [LiveOverflow](https://www.youtube.com/@LiveOverflow) about Minecraft exploiting.

If you haven't seen his channel before and you're interest in cyber security I highly recommend him! This minecraft series was very unusual for him but sort of gamified ethical hacking.
In this series his playing on his own server and challenged viewers to try to discover it and ofcourse, after a few episodes it was discovered, people had scanned the internet for minecraft servers that had his name in the description.
His server had long since been shut down by the time I found the series so I wasn't going to hunt for his but atleast now I had an idea of how that person found our own server.

I decided to try build the tool myself (atleast a basic one) using python and see what I could discover on my own.

I wanted to understand the process from the ground up:

1. How does a port scanner actually work?
2. Why can't I just assume Minecraft is running on port `25565`?
3. How can I tell whether an open port is actually Minecraft?
4. How does the Minecraft protocol identify itself?
5. Why does scanning thousands of ports take so long?
6. How can I make the scanner perform many network checks at once?

That became the project.

---

# Part 1: The Simplest Possible Port Scanner

Unlike most games and Bedrock edition of minecraft, java edition uses TCP over UDP for client-server connection.

An IP address identifies a machine, while a port identifies a network service listening on that machine.

For example:

```
192.168.1.100:80
192.168.1.100:443
192.168.1.100:25565
```

These all refer to the same machine, but potentially different services.

Minecraft Java Edition commonly uses port 25565, but there's nothing requiring a server to use that port. The server owner can configure Minecraft to listen somewhere else.

That meant simply checking 25565 wasn't enough.

I started with the most basic possible question:

    Can I establish a TCP connection to this port?

In Python, that can be done with the socket library:

```
import socket

def check_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)

    try:
        sock.connect((host, port))
        return True
    except:
        return False
    finally:
        sock.close()
```
This is a simple attempt at a tcp connection, if it succeeds then we know something is listening on it (open) and if not its probably closed.
An open port could be anything, a website, FTP, SSH. Just being able to establish it's open wasn't going ot be much help in identifying minecraft servers!
Even if the open port on an address was 25565 (default address) that didn't mean that it was minecraft running.


# Part 2: From "Open Port" to "Minecraft Server"

The next question became:

    How can I actually identify a Minecraft server?

now I needed to establish how Minecraft communicates over the network.

Minecraft doesn't just accept an arbitrary TCP connection and announce that it's minecraft, it expects clients to communicate using its network protocol.
The devs definitely didn't expect some idiot (me) to try pinging servers from outside of minecraft with some code.
Instead of standard 4-byte integers minecraft uses VarInts


# Part 3: Learning About VarInts

I now knew Minecraft uses a variable-length integer format called a VarInt for many integer values in its protocol.

Instead of always storing an integer in a fixed number of bytes, a VarInt stores it using groups of 7 bits with the first 7 bits contain part of the number.

The remaining bit tells us whether another byte follows.

If the continuation bit is 0, we're done.

If it's 1, there are more bytes.

For example, a small number like 5 only needs one byte because it fits comfortably inside 7 bits. (0000101)

Larger numbers are split across multiple bytes.

This is useful for a network protocol because many of the numbers Minecraft sends are small, so they can be represented using fewer bytes.
# Part 4: Implementing VarInt Encoding

now understanding the concept, I implemented my own VarInt encoder (with the help of some guides)

```
def encode_varint(value):
    value &= 0xFFFFFFFF
    out = bytearray()

    while True:
        byte = value & 0x7F
        value >>= 7

        if value:
            byte |= 0x80

        out.append(byte)

        if not value:
            break

    return bytes(out)
```
The important line is:

```
byte = value & 0x7F
```
This extracts the lowest 7 bits.

Then:

```
value >>= 7
```
moves the remaining bits down so they can be processed on the next iteration.

If there are still bits remaining:

```
byte |= 0x80
```

sets the continuation bit.

The resulting bytes are then returned.

I also needed the opposite operation: decoding a VarInt so we could actually understand what the server was saying back

```
def decode_varint_bytes(data, offset=0):
    result = 0
    shift = 0

    while True:
        if offset >= len(data):
            raise ValueError("Incomplete VarInt")

        byte = data[offset]
        offset += 1

        result |= (byte & 0x7F) << shift

        if not (byte & 0x80):
            return result, offset

        shift += 7

        if shift > 35:
            raise ValueError("Invalid VarInt")
```
This just takes VarInt and put it back to normal

Instead of taking an integer and splitting it into bytes, it takes bytes and reconstructs the integer.

The reason the function returns both result and offset is important.

Minecraft packets contain multiple fields one after another:

[packet ID][length][data...]

After decoding the first VarInt, I need to know where the next field starts.

That's what offset represents.
# Part 5: Building a Minecraft Probe

Once I understood the basic packet structure, I could make something more useful than just checking whether a port was open.

I could connect to a port and ask:

    "are you minecraft?"

The basic flow is:

```
TCP connection -> Minecraft Handshake -> Status Request -> Minecraft Status Response -> JSON
```
The Minecraft status protocol is particularly useful because the server can provide information such as:

    server version

    protocol version

    maximum players

    current players

    server description

The first step is opening the TCP connection:

```
reader, writer = await asyncio.open_connection(host, port)
```

Then I construct the Minecraft handshake.

```
host_bytes = host.encode("utf-8")

handshake = (
    encode_varint(0)
    + encode_varint(MC_PROTOCOL)
    + encode_varint(len(host_bytes))
    + host_bytes
    + struct.pack(">H", port)
    + encode_varint(1)
)
```

The port is slightly different:

```
struct.pack(">H", port)
```

Here I'm converting the Python integer into a two-byte unsigned integer.

```
 >H = big endian unsigned 16-bit integer
```
A port fits naturally into 16 bits because the valid port range is:

0 - 65535

Finally:

encode_varint(1)

specifies that the next protocol state is the status state.
# Part 6: Asking the Server for Its Status

The handshake doesn't actually ask the server for its information.

It just tells the server:

    "I'm connecting using this protocol version, and I want to enter the status state."

I then send a status request:

```
status_request = encode_varint(0)

writer.write(
    encode_varint(len(status_request)) + status_request
)

await writer.drain()
```

The packet consists of:

```
[packet length][packet data]
```

Once this is sent, I wait for the server's response.
# Part 7: Reading the Response

The server first sends the length of its response packet.

```
packet_length = await read_varint(reader)
```

Then I read exactly that many bytes:

```
packet = await reader.readexactly(packet_length)
```
This is important because TCP is a stream of bytes, not a message-based protocol.

If a server sends 500 bytes, I can't assume that one read() call will give me all 500 bytes.

I might receive:

100, 200, 200 bytes

over several reads.

readexactly() handles that by continuing until the requested number of bytes has been received.

My VarInt reader looks like this:

```
async def read_varint(reader):
    result = 0
    shift = 0

    while True:
        byte = (await reader.readexactly(1))[0]

        result |= (byte & 0x7F) << shift

        if not (byte & 0x80):
            return result

        shift += 7

        if shift > 35:
            raise ValueError("Invalid VarInt")
```
It reads one byte at a time and reconstructs the integer.
# Part 8: Finding the JSON

Once I've received the packet, I start parsing it.

First I read the packet ID

Then I read the length of the JSON data and extracting bytes

```
json_length, offset = decode_varint_bytes(packet, offset)

data = json.loads(
    packet[offset:offset + json_length]
    .decode("utf-8")
)
```
This is a nice example of how several layers of data representation fit together to transmit data over a network:

```
TCP -> raw bytes -> Minecraft packet -> VarInts + data -> UTF-8 JS -> Python dictionary
```
The resulting dictionary contains the server information.

```
{
    "version": {
        "name": "1.21.x",
        "protocol": 777
    },
    "players": {
        "online": 3,
        "max": 20
    }
}
```

I can then extract the useful fields:

```
players = data.get("players", {})

version = data.get("version", {})

return {
    "port": port,
    "players_online": players.get("online", 0),
    "players_max": players.get("max", 0),
    "version": version.get("name", "Unknown"),
    "protocol": version.get("protocol", "Unknown"),
}
```

At this point I had something that could take a single port and determine whether it was responding like a Minecraft server.

# Part 9: The Problem With Doing It One Port at a Time

The single-port probe worked, but there was an obvious problem.

There are 65,535 TCP ports available on an IPv4 address.

Even if I only wanted to check a few thousand ports, doing this:

check port
wait
check port
wait
check port
wait
check port
wait
...

would take a long time.

Network operations spend a lot of their time waiting.

The CPU isn't doing anything useful during most of that wait.

This is where asynchronous programming became useful.
# Part 10: Discovering asyncio

Python's asyncio library allows me to have many network operations in progress at the same time.

This isn't the same as running hundreds of pieces of Python code on hundreds of CPU cores.

It's concurrency.

While one network operation is waiting, the event loop can work on another.

For example:

```
async def check_port(host, port):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            TCP_TIMEOUT
        )

        return True

    except ConnectionRefusedError:
        return False
```
The important part is:
```
await
```
When Python reaches an await for an operation that is waiting on the network, the event loop can go and work on another task.

# Part 11: Building a Worker Pool

I didn't want to create tens of thousands of connections simultaneously, though.

Instead, I created a queue of jobs and a fixed number of workers.

```
TCP_WORKERS = 200
```
200 workers pretty much means no more than 200 ports will be checked at once.

Each worker takes a port from the queue, checks it, and then takes another.

The important part of my worker pool looks like this:

```
async def worker():
    while not stop_requested:
        try:
            item = queue.get_nowait()
        except asyncio.QueueEmpty:
            return

        try:
            result = await worker_fn(item)
        except Exception as e:
            print(f"Worker error on {item}: {e!r}")
            result = None

        state["done"] += 1
        results.append((item, result))
```
And I create the workers with:
```
workers = [
    asyncio.create_task(worker())
    for _ in range(n)
]

await asyncio.gather(*workers)
```

This made a huge difference compared with checking every port sequentially.

# Part 12: Splitting the Scanner Into Two Phases

At this point the project had become two separate operations.
Phase 1 — TCP discovery

Ask:

    Is anything listening on this port?

port 25560 → closed
port 25561 → closed
port 25562 → open
port 25563 → closed
port 25564 → open

Phase 2 — Minecraft identification

Only test the ports that were actually open:

25562 → Minecraft?
25564 → Minecraft?

This avoids wasting time performing a full Minecraft handshake against ports where nothing is listening.

The final steps were then 
1. defining the port range
2. attempting to establish a tcp request to see if it's open
3. Take all the open ports and attempt to communicate with VarInt
4. If that's a success decode the json to get info about the server.

# Part 13: Making It Into a Discord Bot

Congrats on reading this far! 

Once the scanner was working from the command line, I wanted my friends to be able to see what happened to us aswell

Instead of running the program locally and showing them terminal output, I integrated it into a Discord bot.

The bot accepts commands such as:

!test <host> <port>
!work <start> <end> <host>
!stop

For example:

!test 123.456.789 25565

performs a single Minecraft port check on the given address.

The larger command:

!work 25560 25600 123.456.789

starts the two-phase scan.
# Part 14: Progress Reporting

Because the scan can take a while, I also wanted the bot to show progress.

The scanner keeps track of:

state = {
    "done": 0,
    "found": 0
}

Then a separate async task periodically reports the progress:

```
async def progress_reporter(ctx, label, state, total, found_label, unit):
    started = time.monotonic()

    try:
        while True:
            await asyncio.sleep(PROGRESS_INTERVAL)

            elapsed = time.monotonic() - started
            speed = state["done"] / elapsed if elapsed > 0 else 0
            pct = state["done"] / total * 100 if total else 100

            await send_message(
                ctx,
                f"{label}\n"
                f"Progress: `{pct:.1f}%`\n"
                f"Checked: `{state['done']:,}/{total:,}`\n"
                f"Speed: `{speed:,.0f} {unit}`\n"
                f"{found_label}: `{state['found']}`",
            )

    except asyncio.CancelledError:
        pass
```

This is another good example of why async is useful.

The scanner can be doing network operations while the progress reporter sleeps.

The two tasks don't block each other.

# Part 15: What I Learned (The most important part!)


The biggest thing I took away from this project wasn't actually the scanner itself.

It was learning how different layers of software fit together.

At the beginner I thought that every mc server had an address, just like a website so finding them should be easy.

But there are several steps between an IP address and actually identifying the software running there.

I ended up learning about:

    TCP connections and ports

    sockets

    network timeouts

    TCP streams

    binary data

    byte encoding

    VarInts

    Minecraft's handshake and status protocol

    JSON parsing

    asynchronous programming

    concurrency

    worker pools

    queues

    Discord bots

The project also gave me a much better understanding of what network scanners are actually doing.

A port scanner isn't magically "finding Minecraft servers." At the lowest level, it's asking computers whether particular network doors are open. Application-level probing can then use the protocol that the expected service speaks to determine what is actually behind those doors.

And that brought me back to the original question: how did that random person find our server?

I still couldn't say with certainty that this was how our particular server was discovered, but building the scanner gave me a much better understanding of how a server that feels "private" can still be discoverable if it is reachable from the public internet.

I'm still not a pro at all the tools used, especially asynchronous programming, but I know much more than I did before diving down this rabbit hole! Thanks for reading!