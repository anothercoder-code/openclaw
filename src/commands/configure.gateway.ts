import type { OpenClawConfig } from "../config/config.js";
import { resolveGatewayPort } from "../config/config.js";
import { isValidEnvSecretRefId, type SecretInput } from "../config/types.secrets.js";
import {
  maybeAddTailnetOriginToControlUiAllowedOrigins,
  TAILSCALE_DOCS_LINES,
  TAILSCALE_EXPOSURE_OPTIONS,
  TAILSCALE_MISSING_BIN_NOTE_LINES,
} from "../gateway/gateway-config-prompts.shared.js";
import { findTailscaleBinary } from "../infra/tailscale.js";
import type { RuntimeEnv } from "../runtime.js";
import { resolveDefaultSecretProviderAlias } from "../secrets/ref-contract.js";
import { validateIPv4AddressInput } from "../shared/net/ipv4.js";
import { note } from "../terminal/note.js";
import { buildGatewayAuthConfig } from "./configure.gateway-auth.js";
import { confirm, select, text } from "./configure.shared.js";
import {
  guardCancel,
  normalizeGatewayTokenInput,
  randomToken,
  validateGatewayPasswordInput,
} from "./onboard-helpers.js";

type GatewayAuthChoice = "token" | "password" | "trusted-proxy";
type GatewayTokenInputMode = "plaintext" | "ref";

export async function promptGatewayConfig(
  cfg: OpenClawConfig,
  runtime: RuntimeEnv,
): Promise<{
  config: OpenClawConfig;
  port: number;
  token?: string;
}> {
  const portRaw = guardCancel(
    await text({
      message: "Gateway 端口",
      initialValue: String(resolveGatewayPort(cfg)),
      validate: (value) => (Number.isFinite(Number(value)) ? undefined : "端口无效"),
    }),
    runtime,
  );
  const port = Number.parseInt(String(portRaw), 10);

  let bind = guardCancel(
    await select({
      message: "Gateway 绑定模式",
      options: [
        {
          value: "loopback",
          label: "回环地址（仅本机）",
          hint: "绑定到 127.0.0.1，更安全，仅允许本机访问",
        },
        {
          value: "tailnet",
          label: "Tailnet（Tailscale IP）",
          hint: "仅绑定到你的 Tailscale IP（100.x.x.x）",
        },
        {
          value: "auto",
          label: "自动（回环 → 局域网）",
          hint: "优先使用回环地址；不可用时回退到所有网卡",
        },
        {
          value: "lan",
          label: "局域网（所有网卡）",
          hint: "绑定到 0.0.0.0，局域网内任意设备可访问",
        },
        {
          value: "custom",
          label: "自定义 IP",
          hint: "指定固定 IP，不可用时回退到 0.0.0.0",
        },
      ],
    }),
    runtime,
  );

  let customBindHost: string | undefined;
  if (bind === "custom") {
    const input = guardCancel(
      await text({
        message: "自定义 IP 地址",
        placeholder: "192.168.1.100",
        validate: validateIPv4AddressInput,
      }),
      runtime,
    );
    customBindHost = typeof input === "string" ? input : undefined;
  }

  let authMode = guardCancel(
    await select({
      message: "Gateway 认证方式",
      options: [
        { value: "token", label: "令牌", hint: "推荐默认选项" },
        { value: "password", label: "密码" },
        {
          value: "trusted-proxy",
          label: "受信任代理",
          hint: "部署在反向代理后（Pomerium、Caddy、Traefik 等）",
        },
      ],
      initialValue: "token",
    }),
    runtime,
  ) as GatewayAuthChoice;

  let tailscaleMode = guardCancel(
    await select({
      message: "Tailscale 暴露方式",
      options: [...TAILSCALE_EXPOSURE_OPTIONS],
    }),
    runtime,
  );

  // Detect Tailscale binary before proceeding with serve/funnel setup.
  // Persist the path so getTailnetHostname can reuse it for origin injection.
  let tailscaleBin: string | null = null;
  if (tailscaleMode !== "off") {
    tailscaleBin = await findTailscaleBinary();
    if (!tailscaleBin) {
      note(TAILSCALE_MISSING_BIN_NOTE_LINES.join("\n"), "Tailscale 警告");
    }
  }

  let tailscaleResetOnExit = false;
  if (tailscaleMode !== "off") {
    note(TAILSCALE_DOCS_LINES.join("\n"), "Tailscale");
    tailscaleResetOnExit = Boolean(
      guardCancel(
        await confirm({
          message: "退出时是否重置 Tailscale serve/funnel？",
          initialValue: false,
        }),
        runtime,
      ),
    );
  }

  if (tailscaleMode !== "off" && bind !== "loopback") {
    note("Tailscale 要求 bind=loopback，已自动调整为 loopback。", "提示");
    bind = "loopback";
  }

  if (tailscaleMode === "funnel" && authMode !== "password") {
    note("Tailscale funnel 需要使用密码认证。", "提示");
    authMode = "password";
  }

  // trusted-proxy + loopback is valid when the reverse proxy runs on the same
  // host (e.g. cloudflared, nginx, Caddy). trustedProxies must include 127.0.0.1.
  if (authMode === "trusted-proxy" && tailscaleMode !== "off") {
    note("受信任代理认证与 Tailscale serve/funnel 不兼容，已禁用 Tailscale。", "提示");
    tailscaleMode = "off";
    tailscaleResetOnExit = false;
  }

  let gatewayToken: SecretInput | undefined;
  let gatewayTokenForCalls: string | undefined;
  let gatewayPassword: string | undefined;
  let trustedProxyConfig:
    | { userHeader: string; requiredHeaders?: string[]; allowUsers?: string[] }
    | undefined;
  let trustedProxies: string[] | undefined;
  let next = cfg;

  if (authMode === "token") {
    const tokenInputMode = guardCancel(
      await select<GatewayTokenInputMode>({
        message: "Gateway 令牌来源",
        options: [
          {
            value: "plaintext",
            label: "生成并保存明文令牌",
            hint: "默认",
          },
          {
            value: "ref",
            label: "使用 SecretRef",
            hint: "保存环境变量引用，而不是明文",
          },
        ],
        initialValue: "plaintext",
      }),
      runtime,
    );
    if (tokenInputMode === "ref") {
      const envVar = guardCancel(
        await text({
          message: "Gateway 令牌环境变量",
          initialValue: "OPENCLAW_GATEWAY_TOKEN",
          placeholder: "OPENCLAW_GATEWAY_TOKEN",
          validate: (value) => {
            const candidate = String(value ?? "").trim();
            if (!isValidEnvSecretRefId(candidate)) {
              return "请使用类似 OPENCLAW_GATEWAY_TOKEN 的环境变量名。";
            }
            const resolved = process.env[candidate]?.trim();
            if (!resolved) {
              return `当前会话中环境变量“${candidate}”不存在或为空。`;
            }
            return undefined;
          },
        }),
        runtime,
      );
      const envVarName = String(envVar ?? "").trim();
      gatewayToken = {
        source: "env",
        provider: resolveDefaultSecretProviderAlias(cfg, "env", {
          preferFirstProviderForSource: true,
        }),
        id: envVarName,
      };
      note(`已验证 ${envVarName}。OpenClaw 将保存令牌 SecretRef。`, "Gateway 令牌");
    } else {
      const tokenInput = guardCancel(
        await text({
          message: "Gateway 令牌（留空自动生成）",
          initialValue: randomToken(),
        }),
        runtime,
      );
      gatewayTokenForCalls = normalizeGatewayTokenInput(tokenInput) || randomToken();
      gatewayToken = gatewayTokenForCalls;
    }
  }

  if (authMode === "password") {
    const password = guardCancel(
      await text({
        message: "Gateway 密码",
        validate: validateGatewayPasswordInput,
      }),
      runtime,
    );
    gatewayPassword = String(password ?? "").trim();
  }

  if (authMode === "trusted-proxy") {
    note(
      [
        "受信任代理模式：OpenClaw 信任来自反向代理传递的用户身份。",
        "代理必须先完成用户认证，并通过请求头传递身份信息。",
        "只有来自指定代理 IP 的请求会被信任。",
        "",
        "常见场景：Pomerium、Caddy + OAuth、Traefik + forward auth",
        "文档：https://docs.openclaw.ai/gateway/trusted-proxy-auth",
      ].join("\n"),
      "受信任代理认证",
    );

    const userHeader = guardCancel(
      await text({
        message: "用于传递用户身份的请求头",
        placeholder: "x-forwarded-user",
        initialValue: "x-forwarded-user",
        validate: (value) => (value?.trim() ? undefined : "用户身份请求头不能为空"),
      }),
      runtime,
    );

    const requiredHeadersRaw = guardCancel(
      await text({
        message: "必需请求头（逗号分隔，可选）",
        placeholder: "x-forwarded-proto,x-forwarded-host",
      }),
      runtime,
    );
    const requiredHeaders = requiredHeadersRaw
      ? String(requiredHeadersRaw)
          .split(",")
          .map((h) => h.trim())
          .filter(Boolean)
      : [];

    const allowUsersRaw = guardCancel(
      await text({
        message: "允许用户（逗号分隔，留空表示所有已认证用户）",
        placeholder: "nick@example.com,admin@company.com",
      }),
      runtime,
    );
    const allowUsers = allowUsersRaw
      ? String(allowUsersRaw)
          .split(",")
          .map((u) => u.trim())
          .filter(Boolean)
      : [];

    const trustedProxiesRaw = guardCancel(
      await text({
        message: "受信任代理 IP（逗号分隔）",
        placeholder: "10.0.1.10,192.168.1.5",
        validate: (value) => {
          if (!value || String(value).trim() === "") {
            return "至少需要填写一个受信任代理 IP";
          }
          return undefined;
        },
      }),
      runtime,
    );
    trustedProxies = String(trustedProxiesRaw)
      .split(",")
      .map((ip) => ip.trim())
      .filter(Boolean);

    trustedProxyConfig = {
      userHeader: String(userHeader).trim(),
      requiredHeaders: requiredHeaders.length > 0 ? requiredHeaders : undefined,
      allowUsers: allowUsers.length > 0 ? allowUsers : undefined,
    };
  }

  const authConfig = buildGatewayAuthConfig({
    existing: next.gateway?.auth,
    mode: authMode,
    token: gatewayToken,
    password: gatewayPassword,
    trustedProxy: trustedProxyConfig,
  });

  next = {
    ...next,
    gateway: {
      ...next.gateway,
      mode: "local",
      port,
      bind,
      auth: authConfig,
      ...(customBindHost && { customBindHost }),
      ...(trustedProxies && { trustedProxies }),
      tailscale: {
        ...next.gateway?.tailscale,
        mode: tailscaleMode,
        resetOnExit: tailscaleResetOnExit,
      },
    },
  };

  next = await maybeAddTailnetOriginToControlUiAllowedOrigins({
    config: next,
    tailscaleMode,
    tailscaleBin,
  });

  return { config: next, port, token: gatewayTokenForCalls };
}
