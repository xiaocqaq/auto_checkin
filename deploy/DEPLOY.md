# checkin-panel 部署记录（本机 VPS，2026-10-03）

上游：https://github.com/BingLi37/checkin-panel （commit 3be6953，v0.2.0 附近）

## 拓扑

    https://<你的域名>/checkin/        ← 签到面板（带鉴权）
    https://<你的域名>/checkin-vnc/    ← 可见浏览器（浏览器登录用，带鉴权）
        │  nginx: location ^~ + access_by_lua_file 校验（复用 utils_session + 白名单）
        │  鉴权: /etc/nginx-auth/checkin-authz.lua（ALLOW = { xiao = true }）
        ▼
    127.0.0.1:<面板端口> → 容器 8000   FastAPI 面板
    127.0.0.1:<VNC端口> → 容器 6080   noVNC 网页桥（看/操作有头浏览器）
        │
        │  容器内还常开着：Xvfb :99 + x11vnc 127.0.0.1:5900
        ▼
    <宿主网关>:7890  宿主 mihomo（Rule 分流）

## 文件位置

| 用途 | 路径 |
|---|---|
| 源码 + 构建 | /opt/checkin-panel |
| 账号库（唯一副本，明文）| /var/lib/checkin-panel/data |
| 浏览器 profile（OAuth 会话）| /var/lib/checkin-panel/profiles |
| 隐身 Chromium 缓存（~700MB）| /var/lib/checkin-panel/browser |
| 鉴权 lua（线上）| /etc/nginx-auth/checkin-authz.lua |
| 鉴权 lua + 入口脚本（源码副本）| /opt/checkin-panel/deploy/ |
| nginx vhost | <宝塔 vhost 目录>/<你的域名>.conf |

## 运维

```bash
cd /opt/checkin-panel
docker compose ps / logs -f / up -d --build / down
```

改白名单：编辑 /etc/nginx-auth/checkin-authz.lua 顶部 `ALLOW = { xiao = true }`，
`/www/server/nginx/sbin/nginx -s reload`（不用重启容器）。

## 上游改动清单

**子路径适配**
1. `frontend/vite.config.ts` — `base: process.env.CHECKIN_BASE || '/'`
2. `frontend/src/api.ts` — 基址 `${BASE_URL.replace(/\/$/,'')}/api`
3. `Dockerfile` — `ARG CHECKIN_BASE` 注入

**构建加速（国内）**
4. `Dockerfile` — npm(registry.npmmirror.com) / pip(腾讯) / apt(腾讯 deb822) 全走镜像
5. `Dockerfile` — 装 `xvfb x11vnc novnc websockify`

**出口代理（本机在国内）**
6. `panel/newapi.py` `_client()` — 加 `CHECKIN_HTTP_PROXY` 全局 HTTP 出口
7. `panel/vendor/utils/browser.py` — `CHECKIN_BROWSER_PROXY=1` 时浏览器全走代理
8. `docker-compose.yml` — `HTTP_PROXY/HTTPS_PROXY` 让**浏览器二进制下载**也走代理

**浏览器会话稳定（2026-10-03 加）**
9. `panel/vendor/utils/browser.py` `stealth_args_for()` + `_stable_fingerprint_seed()`
   — 指纹种子按 profile 路径固定（cloakbrowser 默认每次随机抽，同一 profile
   天天变「新设备」）。**必须 `stealth_args=False` + `args=[...]` 覆盖**；
   `stealth_args` 是布尔开关不是列表，直接传列表会被静默忽略（踩过）。
10. `panel/vendor/utils/browser.py` `release_stale_profile_lock()`
    — 每次启动前清掉崩溃残留的 `Singleton*` 锁（见「关键坑 3」），
    只清确认已死的锁，活锁绝不碰。

**有头浏览器可见性（VNC）**
11. `deploy/entrypoint.sh` — 启动 Xvfb/x11vnc/noVNC 再 exec run.py；启动时清 profile 锁
12. `Dockerfile` — 拷入口脚本、改 `CMD`、修 noVNC 的 `options.add` bug
13. `docker-compose.yml` — <VNC端口> 端口、`CHECKIN_VNC` 开关、部署环境指定的容器子网

**图形验证码识别（2026-10-12 加）**
14. `panel/captcha.py`（新增）— 视觉识别模块：`vision_enabled()` / `solve_image()` /
    `_clean()` / `PROMPT`；`solve_image` 把 base64 图 POST 到网关 `/chat/completions`
    （model=`auto`），**显式带 `proxy=CHECKIN_HTTP_PROXY`**（容器内 `<你的网关域名>`
    解析到自己的 127.0.0.1，直连必 ConnectError）。
15. `panel/newapi.py` — `CAPTCHA_ATTEMPTS = 3`；`_fetch_captcha()`（取 `{captcha_id,
    captcha_image}`）+ `_retry_with_captcha()`（识别 → 带 `captcha_answer` 重试，
    每次重试**重新取图**，因为答案只在新鲜时有效）；接进 `_check_in_endpoint()`。
16. `docker-compose.yml` — `CHECKIN_VISION_BASE_URL/MODEL/API_KEY`；key 放 `.env`
    （chmod 600，已 gitignore），不写进 compose。

**杂项**
17. `CONTEXT.md` — 上游引用了但未提交，建最小占位

**自建后端站点：relay4（2026-10-12 加）**
18. `panel/vyce.py`（新增）— 该站**不是 New API 分支**：路由全在 `/user/*`，登录前置
    一道 **SHA-256 工作量证明（PoW）**，签到是 `POST /user/daily-reward/claim`
    （无 body、无验证码、不需要浏览器）。
    - PoW：找 nonce `g` 使 `lz(sha256(f'vyce-auth-seal-v4:{id[:32]}:{sha256_hex(...)}:{g}:{epoch}')) >= difficulty`；
      实测 difficulty=17 → 约 13 万次哈希、**0.04~0.9 秒**（快慢差 20 倍正常）。
    - 凭据：登录返回的 `session_xxx` **同时是 token 和 cookie 值**，`Max-Age=604800`（7 天），
      带上就能 claim，**不需要 Bearer**。存进面板 session 字段，下次先试探、401 再补登录。
    - 设备指纹按账号派生且**必须稳定**（每次换"新设备"最招风控，与浏览器指纹那次同因）。
19. `panel/service.py` `_attempt()` — 先跑一次廉价探测（`/user/daily-reward` 未登录回
    401 `invalid_session`），命中就整条走 vyce，不碰 `newapi.py` 那套 `/api/*`。
20. `panel/newapi.py` `probe()` — 同样先问一次该路由，命中就标出真实机制
    （`checkin_path=/user/daily-reward/claim`、`quota_per_unit=1.0`），否则 UI 会把它
    误显示成 `login_bonus`。

**第三套后端：Sub2API（2026-10-12 加，站点：relay6 relay6 / relay7 relay7）**
21. `panel/sub2api.py`（新增）— 这两站跑的是 **Sub2API**（`Subscription to API Conversion
    Platform`，Vue SPA），接口全在 `/api/v1/*`，New API 那套探测全 404。签到相关：
    - `GET /api/v1/check-in/status` → `{enabled, checked_in_today, current_streak, today_reward, free_balance}`
    - `POST /api/v1/check-in` `{turnstile_token: ""}` → 已签则 `already_checked_in`
    - 登录 `POST /api/v1/auth/login {email, password, turnstile_token}` → `{access_token, refresh_token, user}`
    - `POST /api/v1/auth/refresh {refresh_token}` 换新 access_token
22. `panel/sub2api.py` `browser_login()` — **登录必须走完整浏览器流程**。三条实测：
    - **只有登录要 Turnstile，签到不要**（`turnstile_required: false`）→ 日常签到纯 HTTP，
      不必每天开浏览器。
    - 登录的 Turnstile **必须 headless=False**（无头必被 Cloudflare 判为机器人，widget 是空框）。
      且复选框画在 div 上、不是 `<input>`，面板原有的 `_click_turnstile` 找不到 ——
      要按坐标点 `.turnstile-wrapper` 左侧约 24px，偏移轮流试几次。
    - **别只 mint 一个 token 再拿去 HTTP 登录**：实测连续 6 轮全失败；而在登录页上把
      「点 Turnstile → 填表 → 点 Sign In」走完几乎一次就成（token 与页面/表单上下文绑定）。
      登录成功后从 `localStorage` 读 `auth_token`/`refresh_token` 存进 DB（JWT→access_token，
      refresh→session）。refresh_token 可长期复用，**浏览器只需成功一次**。
23. `panel/service.py` / `panel/newapi.py` — 与 vyce 同样加一次廉价探测分流
    （`/api/v1/check-in/status` 未登录回 401 JSON），命中就整条走 sub2api。
    **未实现抽奖**（用户 2026-10-12 明确说「只签到就行，不搞抽奖」）。

## 关键坑（都实测踩过）

1. **容器网络必须与宿主防火墙规则一致**
   为实际使用的容器子网放行代理端口，并使用对应网桥可达的代理地址。
   子网或代理网关配置不匹配时，容器请求可能出现 `ConnectTimeout`。

2. **浏览器二进制下载也要走代理**
   不设 `HTTP_PROXY`：国内直连 cloakbrowser.dev 超时。更要命的是这个下载是**同步
   阻塞**的，会卡死整个事件循环 → 面板 health 和页面全无响应 → nginx **504**。
   日志线索：`Primary download failed (The read operation timed out)`。

3. **`TargetClosedError: Missing X server or $DISPLAY` 有两层原因**
   - 表层：面板的「浏览器登录」**故意开有头浏览器**（要人手动点 GitHub 授权），
     无显示器的容器里必然崩。解法 = Xvfb + VNC。
   - 深层：浏览器被强杀后 profile 留下 `SingletonLock`，下次启动 Chromium 报
     「profile appears to be in use by another Chromium process (NNN) on another
     computer」，它想弹确认框又弹不出来（无 GUI），最终吐出的却是那句误导性的
     "Missing X server"。**看到这个报错先查 profile 锁**，别一头扎进显示器方向。
     已在 entrypoint 里每次启动清一遍。

4. **Debian noVNC 1.6.0 有个白屏 bug**
   `app/ui.js` 的 `addOption()` 用 `selectbox.options.add(optn)`
   （`HTMLSelectElement.options` 是 `HTMLOptionsCollection`，没有 `add`），
   现代浏览器直接抛 `selectbox.options.add is not a function`，整个界面只剩错误框。
   修：换成 `appendChild`（已写进 Dockerfile，带 `grep -q` 断言防回退）。

5. **noVNC 的 `isSecureContext` 报错是误报**
   自动化浏览器（如 Playwright/CDP）里 `window.isSecureContext` 返回 `undefined`，
   noVNC 把它当不安全上下文，弹 "Running without HTTPS"。**真实浏览器不会有**
   （容器内真实 Chromium 实测 `isSecureContext: True`、canvas 正常出画面）。
   验证 VNC 必须用真 Chromium，别用自动化浏览器下结论。

6. **`^~` 必须**（与 /repo、/book1 同理）
   宝塔的 `location ~ .*\.(js|css)?$` 正则优先级高于普通前缀 location。

7. **「GitHub 登录存不住」不是本面板的锅**（2026-10-03 实测澄清）
   实测 profile 里 GitHub 登录**一直活着**：`just` 的 `github/just/Default/Cookies`
   有 `user_session`（滚动 14 天）+ `logged_in`/`dotcom_user`/`_octo`/`_device_id`
   （滚动 365 天），浏览器打开 github.com 实测 `meta[user-login]=<你的 GitHub 用户名>`、
   没有 Sign in 链接 —— 即登录态有效。
   真正会「丢」的是**会话级 cookie**（`_gh_sess`、`color_mode` …，关浏览器即失）
   和 GitHub 本身的安全策略：跨 IP / 跨指纹访问会触发风险校验、要求重新验证，
   所以看起来像「登录存不住」。触发因素里**指纹每次变随机**是可修的一条（见改动 9），
   IP 由 mihomo 节点决定（同一节点 = 同一 IP）。
   若某站点确实要「退出再登录」才给签到（login_bonus），那是**站点机制**，不是 bug——
   panel 在 `browser_login` 里已对这类站点主动登出再登，属于设计行为。

8. **图形验证码站：别把 `max_tokens` 给窄**（2026-10-12 实测踩过）
   relay3 这类站把签到和一张图形码绑在一起，识别走网关 `auto` 模型。坑在于
   `auto` 会路由到**推理模型**（实测 deepseek-v4.1-flash），思考过程也计入
   `completion_tokens` —— 给 `max_tokens=200` 时它先把预算烧在 `reasoning_content` 上，
   `content` 直接空 → `solve_image` 返回 None → 面板报「请输入验证码」。
   现象很像「没连上网关」，其实是模型答了但被截断。**给到 1500 即可**。
   排查这类静默失败时设 `CHECKIN_DEBUG=1`，`captcha.solve_image` 会打印异常栈；
   但「content 为空」不抛异常，需要直接打印原始 `choices`（见 dbg7 思路）。

9. **不是所有站都是 New API 分支 —— 先看路由前缀**（2026-10-12 实测）
   面板整套 `newapi.py` 吃的是 `/api/status`、`/api/user/login`、`/api/user/checkin`。
   `relay4` 是**自建后端**：路由全在 `/user/*`，前端是 Vite SPA（`/api/status` 被
   SPA 兜底成 HTML 200，`_body` 读成「非 JSON 响应」），探测于是把它判成 `login_bonus`
   —— **不诚实但也不报错**，最容易被当成「这站签到机制特殊」而查错方向。
   判据：站点有没有 `/api/status` 这个 JSON。没有就是另一套，去读它前端 JS（找
   `/user/`、`/api/` 字面量 + 请求封装函数），别硬套 New API。
   接入方式：单独一个模块 + 在 `_attempt()`/`probe()` 开头加一次廉价探测分流。

10. **PoW / 图形验证码都别当"要人工"** —— 两种纯 CPU 挑战都可直接算
    自建后端可能用工作量证明代替验证码（relay4 用 SHA-256 PoW，difficulty 17）。
    这不是「必须开浏览器」的信号：Python `hashlib` 双侧 JSON 与前端 `crypto.subtle`
    对得上，实测 0.04~0.9 秒解完。**先试算，别急着上无头浏览器。**

11. **Cloudflare Turnstile：token 是绑定页面上下文的**（2026-10-12 实测）
    踩过两次同一个坑，值得单独记：
    - **别「单独 render 一个 token」再拿去 HTTP 登录**。Sub2API 那两站这样连续 6 轮
      全失败；而在登录页上把「点 Turnstile → 填表 → 提交」走完，几乎一次就成。
      结论：**整条流程在同一个页面里做完**，别拆成「先 mint 再 HTTP」。
    - **别在等 widget 前 `wait_for_load_state('networkidle')`**。这类 SPA 有长连接/轮询，
      它必然超时，白等 15 秒；而 Cloudflare 的 widget 在页面稳定前就放弃渲染了。
      实测：加了这 15 秒反而 20 轮点击全落空，不等则 4 轮拿到 token。按固定时间等水合即可。
    - 无头模式下 Cloudflare 一律不给 token（widget 渲染成空框）；**必须 headless=False**
      （容器内 Xvfb `:99`）。复选框可能画在 div 上而非 `<input>`，按坐标点更可靠。

12. **`set -e` 别用在容器 entrypoint 的辅助组件上**（2026-10-12 实测）
    `deploy/entrypoint.sh` 原来 `set -e` + `Xvfb`。`docker restart`/崩溃重启后 `/tmp` 留下
    `/tmp/.X99-lock`，Xvfb 见到残留锁直接退出，`set -e` 顺带把整个 entrypoint 带走 →
    容器陷入「重启 → Xvfb 失败 → 退出」死循环，**面板彻底起不来**。
    辅助组件（Xvfb/x11vnc/noVNC）坏掉只该让「浏览器登录」不可用，绝不能让面板起不来：
    启动前 `rm -f /tmp/.X99-lock`，且不设 `set -e`。

13. **容器 `/dev/shm` 默认只有 64M，Chrome 会崩**（2026-10-12 实测）
    加载较重 SPA 时渲染进程耗尽 `/dev/shm` 直接崩，面板报
    `Locator.count: Target crashed`。compose 里设 `shm_size: 512m`，并根据实际宿主资源调整。

14. **内存压力与 OOM 保护可能终止浏览器**
    跑有头 Chrome 时若内存紧张，渲染进程可能被 OOM 保护终止，表现为 `Target crashed`。
    先检查内存压力和系统日志，减少浏览器并发或增加资源；不要为了浏览器禁用机器级保护。

## 回滚

```bash
cd /www/server/panel/vhost/nginx
# 删掉「中转站签到面板 /checkin」「签到面板 VNC /checkin-vnc」两整段
nginx -t && nginx -s reload
cd /opt/checkin-panel && docker compose down
rm -f /etc/nginx-auth/checkin-authz.lua
# tools.js 去掉 checkin 卡片（备份在同目录 .bak-checkin-*）
```

## 用法提示

- **HTTP 型站点**：填站点地址 + 凭据，签到秒级完成。
- **浏览器型站点**（visit / 重新登录 / OAuth）：单账号 30–120 秒。
- **图形验证码站点**（如 relay3）：面板自动取图 → 网关 `auto` 视觉模型识别 →
  带答案重试，最多 3 次，无需人工。识别失败会明说，不会卡住。
  依赖：`.env` 里的 `CHECKIN_VISION_API_KEY`（<你的网关> 网关 key）有效；网关/代理挂了
  会退化为「识别失败」。换 key：改 `.env` 后 `docker compose up -d --force-recreate`。
- **自建后端站点**（如 relay4）：登录带 SHA-256 工作量证明、签到在 `/user/daily-reward/claim`。
  面板自动算 PoW（0.04~0.9 秒）、用按钮填的账号密码登录、独立模块签到，无需人工、无需浏览器。
  会话有效期 7 天，面板会存下来复用；过期自动重新登录。
  UI 里这站的机制显示为 `endpoint`、签到路径 `/user/daily-reward/claim`（这是面板补丁登记的
  真实路由，不是站点 `/api/*` 上的东西）。
- **「浏览器登录」按钮**：先点它 → 打开 `/checkin-vnc/` → 在网页里操作那个可见
  浏览器完成授权（点掉公告弹窗、点 GitHub 授权、过验证码）→ 授权一次后，
  之后每天自动完成。VNC 页面里点左侧收缩条能看到控制栏。
