#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Проверка публичных VLESS-конфигов на живость.

Три ступени, каждая отсеивает дешёвым способом до того, как включится дорогая:
  1. TCP-коннект на host:port     -- бесплатно, срезает примерно половину
  2. рукопожатие + cdn-cgi/trace  -- нода реально поднимает тоннель
  3. прокачка 256 КБ              -- через тоннель идут байты, а не только SYN

Третья ступень нужна отдельно: узел может ответить на рукопожатие и не
пропустить ни байта полезного трафика. Пинг и скорость тут НЕ меряем -- они
измерялись бы от раннера, а не от того, кто потом пойдёт через ноду.
"""
import argparse
import base64
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = ("https://raw.githubusercontent.com/AvenCores/goida-vpn-configs"
        "/refs/heads/main/githubmirror/%d.txt")
SOURCES = [BASE % i for i in range(1, 27)]
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
TRACE_HOST, TRACE_PATH = "www.cloudflare.com", "/cdn-cgi/trace"
DOWN_HOST = "speed.cloudflare.com"
DOWN_BYTES = 262144
DOWN_PATH = "/__down?bytes=%d" % DOWN_BYTES
# Транспорты, которые понимает mihomo. xhttp/httpupgrade он не запустит,
# так что проверять их -- зря жечь время раннера.
NETS = ("tcp", "raw", "ws", "grpc", "h2", "http")


def log(*a):
    print(time.strftime("[%H:%M:%S]"), *a, flush=True)


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")


def parse_vless(uri):
    if not uri.startswith("vless://"):
        return None
    try:
        u = urllib.parse.urlsplit(uri)
        p = dict(urllib.parse.parse_qsl(u.query))
        host, port, uid = u.hostname, u.port, urllib.parse.unquote(u.username or "")
        if not (host and port and uid):
            return None
        net = p.get("type", "tcp")
        if net not in NETS:
            return None
        sec = p.get("security") or "none"
        sni = p.get("sni") or p.get("host") or host
        fp = p.get("fp") or "chrome"
        st = {"network": net, "security": sec}
        if sec == "reality":
            # Reality без публичного ключа сервера нерабочая по определению:
            # рукопожатие без него не построить, и xray отказывается грузить
            # такой конфиг целиком ("empty password"), унося с собой всю
            # пачку. В списках такого мусора 23%, и это 98% всего брака.
            if not p.get("pbk"):
                return None
            sid = p.get("sid", "")
            if sid:
                try:
                    bytes.fromhex(sid)      # xray падает на нешестнадцатеричном
                except ValueError:
                    return None
            st["realitySettings"] = {"serverName": sni, "fingerprint": fp,
                                     "publicKey": p["pbk"],
                                     "shortId": sid,
                                     "spiderX": p.get("spx", "/")}
        elif sec in ("tls", "xtls"):
            st["security"] = "tls"
            st["tlsSettings"] = {"serverName": sni, "fingerprint": fp,
                                 "allowInsecure": p.get("allowInsecure") in ("1", "true")}
            if p.get("alpn"):
                st["tlsSettings"]["alpn"] = [x for x in p["alpn"].split(",") if x]
        if net == "ws":
            st["wsSettings"] = {"path": p.get("path", "/"),
                                "headers": {"Host": p.get("host") or sni}}
        elif net == "grpc":
            st["grpcSettings"] = {"serviceName": p.get("serviceName", ""),
                                  "multiMode": p.get("mode") == "multi"}
        elif net in ("http", "h2"):
            st["network"] = "http"
            st["httpSettings"] = {"path": p.get("path", "/"),
                                  "host": [p.get("host") or sni]}
        user = {"id": uid, "encryption": p.get("encryption", "none")}
        if p.get("flow"):
            user["flow"] = p["flow"]
        return {"raw": uri, "host": host, "port": port,
                "id": "%s:%s:%s" % (host, port, uid[:8]),
                "outbound": {"protocol": "vless",
                             "settings": {"vnext": [{"address": host, "port": port,
                                                     "users": [user]}]},
                             "streamSettings": st}}
    except Exception:
        return None


def fetch_all():
    def one(url):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8", "ignore")
        except Exception as e:
            log("  источник недоступен: %s (%s)"
                % (url.rsplit("/", 1)[-1], type(e).__name__))
            return ""

    out, seen = [], set()
    with ThreadPoolExecutor(max_workers=8) as ex:
        for text in ex.map(one, SOURCES):
            if text and "://" not in text:
                try:
                    text = b64d(text)
                except Exception:
                    continue
            for line in text.splitlines():
                n = parse_vless(line.strip())
                if n and n["id"] not in seen:
                    seen.add(n["id"])
                    out.append(n)
    return out


# ------------------------------------------------------------------ socks

def recvall(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise ConnectionError("сокет закрыт")
        buf += c
    return buf


def socks_open(port, host, dst_port, timeout):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        if recvall(s, 2) != b"\x05\x00":
            raise ConnectionError("socks handshake")
        hb = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb
                  + struct.pack("!H", dst_port))
        rep = recvall(s, 4)
        if rep[1] != 0:
            raise ConnectionError("socks reply %d" % rep[1])
        recvall(s, {1: 6, 4: 18}.get(rep[3]) or (recvall(s, 1)[0] + 2))
        return s
    except Exception:
        s.close()
        raise


_CTX = ssl.create_default_context()


def https_get(port, host, path, timeout, max_bytes=4096, deadline=None):
    raw = socks_open(port, host, 443, timeout)
    try:
        sock = _CTX.wrap_socket(raw, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                      "Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
                      % (path, host, UA)).encode())
        buf, end = b"", -1
        while end < 0:
            c = sock.recv(8192)
            if not c:
                break
            buf += c
            end = buf.find(b"\r\n\r\n")
            if len(buf) > 65536:
                break
        head = buf[:end].decode("latin1", "replace") if end >= 0 else ""
        body = buf[end + 4:] if end >= 0 else b""
        got = len(body)
        while got < max_bytes:
            if deadline and time.monotonic() > deadline:
                break
            try:
                c = sock.recv(65536)
            except socket.timeout:
                break
            if not c:
                break
            got += len(c)
            if len(body) < 4096:
                body += c
        return head, body, got
    finally:
        try:
            raw.close()
        except OSError:
            pass


def probe(port, timeout, budget):
    """Рукопожатие, страна выхода, затем прокачка. -> (loc, exit_ip, байт)."""
    head, body, _ = https_get(port, TRACE_HOST, TRACE_PATH, timeout)
    if " 200" not in head.split("\r\n", 1)[0]:
        raise ConnectionError("trace не 200")
    text = body.decode("latin1", "replace")
    loc = re.search(r"^loc=([A-Z]{2})", text, re.M)
    ip = re.search(r"^ip=(\S+)", text, re.M)
    _, _, got = https_get(port, DOWN_HOST, DOWN_PATH, timeout,
                          max_bytes=DOWN_BYTES,
                          deadline=time.monotonic() + budget)
    return (loc.group(1) if loc else "??"), (ip.group(1) if ip else None), got


# ------------------------------------------------------------------ xray

def write_cfg(nodes, base_port):
    cfg = {"log": {"loglevel": "none"}, "inbounds": [], "outbounds": [],
           "routing": {"rules": []}}
    for i, n in enumerate(nodes):
        ob = json.loads(json.dumps(n["outbound"]))
        ob["tag"] = "out%d" % i
        cfg["inbounds"].append({"tag": "in%d" % i, "listen": "127.0.0.1",
                                "port": base_port + i, "protocol": "socks",
                                "settings": {"auth": "noauth", "udp": False}})
        cfg["outbounds"].append(ob)
        cfg["routing"]["rules"].append({"type": "field",
                                        "inboundTag": ["in%d" % i],
                                        "outboundTag": "out%d" % i})
    fd, path = tempfile.mkstemp(suffix=".json", prefix="chk-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    return path


STAT = {"rejected": 0, "fallbacks": 0, "xray_starts": 0, "probe_ok": 0, "probe_fail": 0,
        "probe_secs": 0.0, "slowest": 0.0, "not_ready": 0}

TAG_RE = re.compile(r"tag\s+o(\d+)")


def sanitize(nodes, xray, base_port):
    """Убирает из пачки конфиги, которые xray откажется грузить.

    Раньше это выяснялось падением процесса, после чего пачка делилась
    пополам -- с реальным запуском xray на каждом уровне рекурсии. Замер:
    82 деления на пачку из 300, 419 с против 11 с у чистой пачки.

    `run -test` разбирает конфиг за ~30 мс, без сети и без запуска сервера,
    и в тексте ошибки называет тег виноватого аутбаунда. Так что искать
    перебором нечего: отбрасываем названного и проверяем снова.
    """
    good = list(nodes)
    for _ in range(len(nodes)):
        cfg = write_cfg(good, base_port)
        try:
            r = subprocess.run([xray, "run", "-test", "-c", cfg],
                               capture_output=True, text=True, timeout=60)
        finally:
            os.unlink(cfg)
        if r.returncode == 0:
            return good
        m = TAG_RE.search(r.stdout + r.stderr)
        if not m or int(m.group(1)) >= len(good):
            # Ошибка не про конкретный аутбаунд. Выбрасывать всю пачку тут
            # нельзя -- так тихо теряются сотни живых нод; проверяем поштучно.
            STAT["fallbacks"] += 1
            log("  -test без тега, перехожу на поштучную: %s"
                % (r.stdout + r.stderr).strip()[-140:])
            return sanitize_each(good, xray, base_port)
        STAT["rejected"] += 1
        good.pop(int(m.group(1)))
        if not good:
            break
    return good


def sanitize_each(nodes, xray, base_port):
    """Запасной путь: каждый конфиг проверяется отдельным -test (~15 мс)."""
    def ok(n):
        cfg = write_cfg([n], base_port)
        try:
            return subprocess.run([xray, "run", "-test", "-c", cfg],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL,
                                  timeout=30).returncode == 0
        except Exception:
            return False
        finally:
            try:
                os.unlink(cfg)
            except OSError:
                pass

    with ThreadPoolExecutor(max_workers=16) as ex:
        good = [n for n, v in zip(nodes, ex.map(ok, nodes)) if v]
    STAT["rejected"] += len(nodes) - len(good)
    return good


def wait_ready(port, deadline=15.0):
    """Ждёт, пока xray поднимет инбаунды. Фиксированный sleep тут врал в обе
    стороны: на пачке в 300 инбаундов xray мог не успеть, и живые ноды
    отсеивались как мёртвые, а на маленькой -- зря простаивал."""
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def check_chunk(nodes, xray, base_port, a):
    """Одна пачка нод под одним процессом xray. -> список выживших."""
    nodes = sanitize(nodes, xray, base_port)
    if not nodes:
        return []
    cfg = write_cfg(nodes, base_port)
    proc = subprocess.Popen([xray, "run", "-c", cfg],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    STAT["xray_starts"] += 1
    if not wait_ready(base_port):
        STAT["not_ready"] += 1
        proc.terminate()
        os.unlink(cfg)
        return []
    good = []
    try:
        def one(pair):
            i, n = pair
            t0 = time.monotonic()
            try:
                loc, ip, got = probe(base_port + i, a.timeout, a.budget)
            except Exception:
                STAT["probe_fail"] += 1
                return None
            finally:
                dt = time.monotonic() - t0
                STAT["probe_secs"] += dt
                STAT["slowest"] = max(STAT["slowest"], dt)
            if got < a.min_bytes:
                STAT["probe_fail"] += 1
                return None
            STAT["probe_ok"] += 1
            n["loc"], n["exit"], n["bytes"] = loc, ip, got
            return n

        with ThreadPoolExecutor(max_workers=len(nodes)) as ex:
            for r in ex.map(one, list(enumerate(nodes))):
                if r:
                    good.append(r)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        try:
            os.unlink(cfg)
        except OSError:
            pass
    return good


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--shards", type=int, default=1)
    ap.add_argument("--out", default="alive.txt")
    ap.add_argument("--xray", default="./xray")
    ap.add_argument("--tcp-workers", type=int, default=400)
    ap.add_argument("--tcp-timeout", type=float, default=3.0)
    ap.add_argument("--batch", type=int, default=40)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--budget", type=float, default=10.0)
    ap.add_argument("--min-bytes", type=int, default=200000)
    ap.add_argument("--base-port", type=int, default=31000)
    ap.add_argument("--deadline-min", type=int, default=280)
    ap.add_argument("--limit", type=int, default=0,
                    help="проверить не больше N нод (для замеров)")
    a = ap.parse_args()

    t_end = time.monotonic() + a.deadline_min * 60
    log("тяну источники...")
    nodes = fetch_all()
    log("уникальных конфигов с пригодным транспортом: %d" % len(nodes))
    mine = [n for i, n in enumerate(nodes) if i % a.shards == a.shard]
    log("шард %d/%d -> %d конфигов" % (a.shard, a.shards, len(mine)))

    log("ступень 1: TCP...")
    t0 = time.monotonic()

    def op(n):
        try:
            with socket.create_connection((n["host"], n["port"]),
                                          timeout=a.tcp_timeout):
                return True
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=a.tcp_workers) as ex:
        reach = [n for n, ok in zip(mine, ex.map(op, mine)) if ok]
    log("  порт открыт у %d из %d (%.0f%%), %.0f с"
        % (len(reach), len(mine), 100.0 * len(reach) / max(len(mine), 1),
           time.monotonic() - t0))

    if a.limit:
        reach = reach[:a.limit]
        log("  ограничение --limit: беру %d" % len(reach))

    log("ступень 2+3: рукопожатие, trace и прокачка %d КБ..."
        % (DOWN_BYTES // 1024))
    alive, done, t_probe, complete = [], 0, time.monotonic(), True
    for i in range(0, len(reach), a.batch):
        if time.monotonic() > t_end:
            log("  бюджет времени исчерпан, остановился на %d из %d"
                % (done, len(reach)))
            complete = False
            break
        chunk = reach[i:i + a.batch]
        tb, rb = time.monotonic(), STAT["rejected"]
        alive += check_chunk(chunk, a.xray, a.base_port, a)
        done += len(chunk)
        log("  пачка %3d: %3d нод за %5.1f с, отбраковано %d, живых всего %d"
            % (i // a.batch + 1, len(chunk), time.monotonic() - tb,
               STAT["rejected"] - rb, len(alive)))
    wall = time.monotonic() - t_probe
    probes = STAT["probe_ok"] + STAT["probe_fail"]
    log("ЗАМЕР: стена %.0f с | стартов xray %d | отбраковано конфигов %d "
        "| пачек не поднялось %d | поштучных проверок %d | зондов %d"
        % (wall, STAT["xray_starts"], STAT["rejected"], STAT["not_ready"],
           STAT["fallbacks"], probes))
    log("ЗАМЕР: суммарно в зондах %.0f с, средний %.1f с, самый долгий %.1f с"
        % (STAT["probe_secs"], STAT["probe_secs"] / max(probes, 1), STAT["slowest"]))
    log("ЗАМЕР: эффективная параллельность %.0fx (сумма зондов / стена)"
        % (STAT["probe_secs"] / max(wall, 1)))

    seen, uniq = set(), []
    for n in alive:                    # один сервер приходит под многими
        k = n.get("exit") or n["id"]   # входами -- в списке нужен один раз
        if k not in seen:
            seen.add(k)
            uniq.append(n)
    # Служебная строка едет вместе со списком: потребителю надо знать не
    # только сколько нод пришло, но и весь ли список успели пройти.
    # parse_vless() на ней возвращает None, так что демону она не мешает.
    stats = ("# STATS shard=%d/%d source=%d mine=%d open=%d checked=%d "
             "alive=%d uniq=%d complete=%d secs=%d"
             % (a.shard, a.shards, len(nodes), len(mine), len(reach), done,
                len(alive), len(uniq), 1 if complete else 0, wall))
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(stats + "\n")
        for n in uniq:
            f.write(n["raw"] + "\n")
    log(stats)
    log("ИТОГО: живых %d, после схлопывания по выходному IP %d -> %s"
        % (len(alive), len(uniq), a.out))


if __name__ == "__main__":
    main()
