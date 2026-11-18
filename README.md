# 中转站自动签到面板（定制版）

> 基于 [BingLi37/checkin-panel](https://github.com/BingLi37/checkin-panel)（MIT）的定制分支，
> 在上游基础上**多支持两类后端**并做了一轮工程加固。上游原版只认 New API 系站点。

一个自建的每日签到面板：加账号、看余额、每天自动领。一台机器上跑，不依赖任何外部服务。

优先走 HTTP 协议签到，**只有站点确实拦得住协议**（OAuth 会话过期、Turnstile、WAF）才启动浏览器 ——
所以绝大多数账号的日常签到只是几个 HTTP 请求，快且不吃资源。

---

## 为什么会有这个分支

上游只处理 **New API / One API 系**的中转站（公开面是 `/api/status`、`/api/user/login`、
`/api/user/checkin`）。但实际用到的站点里有两类完全不认这套：

| 后端类型 | 特征 | 上游行为 | 本分支 |
|---|---|---|---|
| **New API 系** | `/api/*`，`/api/status` 返回 JSON | ✅ 支持 | ✅ 支持 |
| **自建后端**（如 relay4） | 路由在 `/user/*`，登录带 **SHA-256 工作量证明** | ❌ 误判成 `login_bonus` | ✅ 新增 `panel/vyce.py` |
| **Sub2API**（如 relay6/relay7） | 路由在 `/api/v1/*`，登录带 **Cloudflare Turnstile** | ❌ 探测全 404，报「检查账号密码」 | ✅ 新增 `panel/sub2api.py` |

后两类硬套上游那套的后果是**「不诚实但不报错」**：探测读不到 `/api/status`，于是把站点判成
`login_bonus`，然后天天报「登录成功但没有签到记录」——最难查的那种失败。

> 站点一律匿名成 `relay1`…`relay15`。这些站不是本项目作者的资产，公开真实域名等于替它们做广告。
> 技术名（New API、Sub2API、Turnstile、Cloudflare、deepseek、mihomo 等）一律保留 ——
> 你要靠它们判断结论适用范围。

---

## 三类站点分别怎么签

### 1. New API 系（上游原生）
直接 POST 签到路由。若站点要 Turnstile token，会用浏览器去 mint 一个再补交。

### 2. 自建后端 + 工作量证明（`panel/vyce.py`）
登录前置一道 **SHA-256 PoW**，不是验证码、也不需要浏览器：

```
找 nonce g，使
  b    = sha256(f'vyce-pow-v4:{salt}:{prefix}:{id}:{g}:{purpose}').hexdigest()
  seal = sha256(f'vyce-auth-seal-v4:{id[:32]}:{b}:{g}:{epoch}').digest()
  前导零 bit 数 >= difficulty
```

实测 `difficulty=17` → 约 13 万次哈希、**0.04~0.9 秒**解完（哈希分布随机，快慢差 20 倍很正常）。
Python `hashlib` 与前端 `crypto.subtle` 结果一致，直接移植即可。

**关键判断**：PoW 和图形验证码都是纯 CPU 挑战，**不是「必须开浏览器」的信号** —— 先试算，别急着上无头浏览器。

### 3. Sub2API + Cloudflare Turnstile（`panel/sub2api.py`）
这类站的登录卡在 Turnstile 上，踩了三个坑，都记在代码注释里：

- **只有登录要 Turnstile，签到不要**。`check-in/status` 里 `turnstile_required` 为 false，
  签到请求的 `turnstile_token` 传空串即可 → **日常签到纯 HTTP**，不必每天开浏览器。
- **登录必须走完整浏览器流程，别拆成「先 mint 一个 token 再 HTTP 登录」**。
  实测那样连续 6 轮全失败；而在登录页上把「点 Turnstile → 填表 → 提交」走完，几乎一次就成
  —— token 与页面/表单上下文是绑定的。
- **别等 `networkidle`**。这类 SPA 有长轮询，它必然超时白等 15 秒，而 Cloudflare 的 widget
  在页面稳定前就放弃渲染了。

登录成功后 `refresh_token` 可长期复用，**浏览器只需成功一次**，之后每天纯 HTTP。

---

## 图形验证码签到（可选）

有些站把签到和一张**图形验证码**绑在一起（后台原话「提高脚本批量签到的成本」）。
面板会：取图 → 调视觉模型识别 → 带答案重试，最多 3 次，每次重取一张图。

识别走任意 OpenAI 兼容的视觉接口，用环境变量配：

```yaml
CHECKIN_VISION_BASE_URL: https://<你的网关域名>/v1
CHECKIN_VISION_MODEL: auto
CHECKIN_VISION_API_KEY: ${CHECKIN_VISION_API_KEY:-}   # 放 .env，别写进 compose
```

未配置时 `captcha.vision_enabled()` 为假，面板会**明说「未配置识别模型」**，不会静默失败。

> ⚠️ **`max_tokens` 别给窄**。`auto` 常路由到**推理模型**，思考过程也计入 `completion_tokens`；
> 给 200 时它先把预算烧在 reasoning 上，`content` 直接空 —— 现象像「没连上网关」，其实是答了但被截断。
> 给到 1500。

---

## 快速开始

**不需要注册、不需要任何外部账号。** 面板跑在你自己的机器上：

```bash
docker compose up -d --build
docker compose logs -f
```

打开 <http://127.0.0.1:8000> 即可。第一次签到前把 `docker-compose.yml` 里的 `TZ` 设对。

默认配置**不含任何环境特定内容**：没有代理、没有外部识别服务、只监听回环地址，
克隆下来直接就能跑。

### 国内 / 被墙环境（可选覆盖层）

被墙的中转站直连不通，需要出口代理。这类配置放在
`deploy/docker-compose.override.example.yml`（示例，按自己环境改）里，叠上去用：

```bash
docker compose -f docker-compose.yml \
               -f deploy/docker-compose.override.example.yml up -d
```

那份示例里包含了我们这套部署的实际取舍：出口代理三件套、子路径挂载、
容器内虚拟显示器（noVNC）。每条都写了「为什么」，也标了哪些是本机特有的、
你那边可以简化。

### 配置项

见 `docker-compose.yml` 的注释，每一条都写了「为什么这么设」。关键几项：

| 变量 | 默认 | 作用 |
|---|---|---|
| `PANEL_SCHEDULER` | `1` | 每日自动签到；`0` 只保留手动触发 |
| `CHECKIN_HTTP_PROXY` / `CHECKIN_PROXY_URL` | 空 | HTTP / 浏览器请求的出口代理，直连得通就不用设 |
| `CHECKIN_BROWSER_PROXY` | 空 | `1` 时浏览器上下文整体走代理 |
| `CHECKIN_VNC` | `0` | `1` 时容器内起 Xvfb + x11vnc + noVNC（「浏览器登录」要看得见画面时用） |
| `CHECKIN_VISION_*` | 空 | 图形验证码识别，不配则那些站签不了 |
| `PANEL_PROMO` | `1` | 推荐卡片；拉不到 GitHub 时设 `0` |

---

## 本分支相对上游的改动

### 新能力
1. `panel/vyce.py` —— 自建后端（PoW 登录）签到
2. `panel/sub2api.py` —— Sub2API（Turnstile 登录）签到
3. `panel/captcha.py` —— 图形验证码走视觉模型识别
4. `panel/newapi.py` —— 图形验证码重试接线（`_fetch_captcha` / `_retry_with_captcha`）
5. `panel/service.py` / `panel/newapi.py` —— 两类新后端的**廉价分流探测**
   （`/user/daily-reward` 与 `/api/v1/check-in/status` 未登录回 401 JSON），
   命中才整条走对应模块。vyce / Sub2API 使用各自的状态与领取协议，明确跳过 New API 的
   status/额度日志二次核对；不会把它们的凭据发送给不兼容的 New API 路径。

### 工程加固（都实测踩过）
6. **子路径部署** —— `frontend/vite.config.ts` 的 `base` 由 `CHECKIN_BASE` 注入
7. **浏览器指纹固定** —— `panel/vendor/utils/browser.py` 按 profile 路径推导稳定种子。
   上游 cloakbrowser 每次随机抽种子，同一 profile 天天变「新设备」，登录态存不住。
   注意 `stealth_args` 是**布尔开关不是列表**，传列表会被静默忽略
8. **崩溃残留的 profile 锁** —— `release_stale_profile_lock()` 启动前清理 `Singleton*`，
   只清确认已死的（主机名 + pid 双判），活锁绝不碰
9. **`/dev/shm` 调大** —— Docker 默认 64M，Chrome 加载较重 SPA 会耗尽导致渲染进程崩溃
   （`Locator.count: Target crashed`）。设 `shm_size: 512m`
10. **entrypoint 不设 `set -e`** —— 辅助组件（Xvfb 等）失败不该让整个入口退出，
    否则容器陷入「重启 → Xvfb 失败 → 退出」死循环，面板彻底起不来
11. **容器出口代理** —— 服务器在国内，被墙站点必须经宿主代理出去
12. **默认配置剥离环境特定项** —— `docker-compose.yml` 只保留通用配置（无代理、
    无外部服务、绑回环），本机特有的取舍挪到
    `deploy/docker-compose.override.example.yml`。这样别人克隆下来直接能跑，
    不会因为照抄一份写死了代理地址的配置而全部超时。
13. **`CHECKIN_VNC` 改为默认关** —— 只有「浏览器登录」需要容器内虚拟显示器；
    不打开时面板照常工作，纯 HTTP 签到完全不受影响

---

## 安全

- 面板**没有登录功能**，账号凭据明文存储（上游 ADR-0003 的设计取舍：单用户、跑自己机器上）。
  默认绑定 `127.0.0.1`；账号 API 不返回密码、session、access token，只返回是否已设置。
  修改账号时凭据留空保留旧值；API 显式传 `null` 或空字符串可清除。
  POSIX 数据库及备份权限为 `0600`，新建数据目录为 `0700`，Windows 仍需配置操作系统 ACL。
- 远程浏览器访问须设置 `PANEL_ALLOWED_ORIGINS`，如 `https://panel.example.com`（不带路径）。
  Host 与写请求来源校验不替代登录鉴权；详见 [部署说明](docs/deploying.md)。
- 想从手机 / 别的设备访问 → 用 Tailscale、WireGuard 之类的**私有网络**，别把端口公开。
- 必须放公网 → **认证 + TLS + 面板端口不对外，三者缺一不可**。做法见 `docs/deploying.md`。
- `.env` 已 gitignore。别把网关 key / 账号密码提交进仓库。
- 仓库自带一个提交前密钥扫描脚本（上游留的，见 `scripts/check_secrets.py`）。

## 许可

MIT（见 `LICENSE`）。本项目基于 [BingLi37/checkin-panel](https://github.com/BingLi37/checkin-panel)，
其中 `panel/vendor/utils/` 来自 [Milly/anyrouter-check-in](https://github.com/Milly/anyrouter-check-in)（BSD-2-Clause）。
第三方组件的完整清单与义务见 `THIRD-PARTY.md`。
