import * as vscode from "vscode";
import { spawn, ChildProcess } from "child_process";

// The extension wraps the publiclocal client: it starts `publiclocal http
// <port>` in the background, reads the link and request feed from its
// output, and shows them in the status bar and an output channel.

let proc: ChildProcess | undefined;
let link = "";
let inspector = "";
let requests = 0;
let status: vscode.StatusBarItem;
let out: vscode.OutputChannel;

export function activate(ctx: vscode.ExtensionContext) {
  out = vscode.window.createOutputChannel("PublicLocal");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = "publiclocal.menu";
  idle();
  status.show();

  ctx.subscriptions.push(
    out,
    status,
    vscode.commands.registerCommand("publiclocal.share", () => share(ctx)),
    vscode.commands.registerCommand("publiclocal.stop", stop),
    vscode.commands.registerCommand("publiclocal.copy", async () => {
      if (!link) return vscode.window.showInformationMessage("Nothing is shared yet.");
      await vscode.env.clipboard.writeText(link);
      vscode.window.setStatusBarMessage("PublicLocal: link copied", 2000);
    }),
    vscode.commands.registerCommand("publiclocal.open", () => link && vscode.env.openExternal(vscode.Uri.parse(link))),
    vscode.commands.registerCommand("publiclocal.inspector", () =>
      inspector ? vscode.env.openExternal(vscode.Uri.parse(inspector)) : vscode.window.showInformationMessage("The inspector starts with the tunnel.")),
    vscode.commands.registerCommand("publiclocal.showLog", () => out.show(true)),
    vscode.commands.registerCommand("publiclocal.menu", menu),
    { dispose: stop },
  );
}

export function deactivate() {
  stop();
}

function idle() {
  status.text = "$(globe) Share";
  status.tooltip = "PublicLocal: share a local port with a public HTTPS link";
  vscode.commands.executeCommand("setContext", "publiclocal.active", false);
}

async function menu() {
  if (!proc) return vscode.commands.executeCommand("publiclocal.share");
  const pick = await vscode.window.showQuickPick(
    [
      { label: "$(copy) Copy link", cmd: "publiclocal.copy", description: link },
      { label: "$(link-external) Open in browser", cmd: "publiclocal.open" },
      { label: "$(search) Open request inspector", cmd: "publiclocal.inspector", description: inspector },
      { label: "$(output) Show request feed", cmd: "publiclocal.showLog" },
      { label: "$(debug-stop) Stop sharing", cmd: "publiclocal.stop" },
    ],
    { placeHolder: link },
  );
  if (pick) vscode.commands.executeCommand(pick.cmd);
}

async function share(ctx: vscode.ExtensionContext) {
  if (proc) {
    const again = await vscode.window.showWarningMessage(`Already sharing ${link}.`, "Stop and share another port", "Keep it");
    if (again !== "Stop and share another port") return;
    stop();
  }
  const cfg = vscode.workspace.getConfiguration("publiclocal");
  const last = ctx.workspaceState.get<string>("port") ?? "3000";
  const port = await vscode.window.showInputBox({
    prompt: "Port to share (or host:port)",
    value: last,
    validateInput: (v) => (/^(\S+:)?\d{1,5}$/.test(v.trim()) ? undefined : "A port number, e.g. 3000"),
  });
  if (!port) return;
  ctx.workspaceState.update("port", port.trim());

  const args = ["http", "--inspect", "127.0.0.1:0", ...cfg.get<string[]>("extraArgs", [])];
  if (cfg.get<boolean>("askForOptions", true)) {
    const opt = await vscode.window.showQuickPick(
      [
        { label: "$(globe) Anyone with the link", args: [] as string[] },
        { label: "$(lock) Password", args: ["password"] },
        { label: "$(mark-github) GitHub sign-in", args: ["github"], description: "users or @org" },
        { label: "$(clock) 30 minutes, one visitor", args: ["--expires", "30m", "--max-visits", "1"] },
        { label: "$(edit) Custom flags", args: ["custom"] },
      ],
      { placeHolder: "Who may open the link?" },
    );
    if (!opt) return;
    if (opt.args[0] === "password") {
      const pw = await vscode.window.showInputBox({ prompt: "Password visitors must enter", password: true });
      if (!pw) return;
      args.push("--password", pw);
    } else if (opt.args[0] === "github") {
      const who = await vscode.window.showInputBox({ prompt: "GitHub users or @organisations, comma separated", placeHolder: "anna,@my-org" });
      if (!who) return;
      args.push("--allow-github", who);
    } else if (opt.args[0] === "custom") {
      const extra = await vscode.window.showInputBox({ prompt: "Flags for publiclocal http", placeHolder: "--expires 2h --note \"staging build\" --host-header localhost" });
      if (extra === undefined) return;
      args.push(...splitArgs(extra));
    } else {
      args.push(...opt.args);
    }
  }
  const server = cfg.get<string>("server", "");
  if (server) args.push("--server", server);
  args.push(port.trim());
  start(cfg.get<string>("path", "publiclocal"), args);
}

function start(bin: string, args: string[]) {
  out.clear();
  const shown = args.map((a, i) => (a.startsWith("--password=") ? "--password=***" : i > 0 && args[i - 1] === "--password" ? "***" : a));
  out.appendLine(`$ ${bin} ${shown.join(" ")}`);
  requests = 0;
  link = inspector = "";
  status.text = "$(sync~spin) Starting tunnel…";
  vscode.commands.executeCommand("setContext", "publiclocal.active", true);
  let p: ChildProcess;
  try {
    p = spawn(bin, args, { env: { ...process.env, NO_COLOR: "1" } });
  } catch (e) {
    return failed(String(e));
  }
  proc = p;
  let buf = "";
  const onLine = (line: string) => {
    out.appendLine(line);
    const fwd = /^Forwarding (https?:\/\/\S+)/.exec(line);
    if (fwd) {
      link = fwd[1];
      status.text = `$(globe) ${link.replace(/^https?:\/\//, "")}`;
      status.tooltip = `${link}\nClick for options`;
      vscode.window.showInformationMessage(`Sharing at ${link}`, "Copy", "Open").then((a) => {
        if (a === "Copy") vscode.commands.executeCommand("publiclocal.copy");
        if (a === "Open") vscode.commands.executeCommand("publiclocal.open");
      });
    }
    const insp = /^Inspector: (http:\/\/\S+)/.exec(line);
    if (insp) inspector = insp[1];
    if (/^\d\d:\d\d:\d\d\s+[A-Z]+\s/.test(line) && link) {
      requests++;
      status.text = `$(globe) ${link.replace(/^https?:\/\//, "")}  $(arrow-down) ${requests}`;
    }
  };
  const feed = (chunk: Buffer) => {
    buf += chunk.toString();
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      onLine(buf.slice(0, i).replace(/\r$/, ""));
      buf = buf.slice(i + 1);
    }
  };
  p.stdout?.on("data", feed);
  p.stderr?.on("data", feed);
  p.on("error", (e: NodeJS.ErrnoException) => {
    if (e.code === "ENOENT") return notInstalled(bin);
    failed(e.message);
  });
  p.on("exit", (code) => {
    if (proc !== p) return;
    proc = undefined;
    if (code && code !== 0 && link === "") failed(buf || `publiclocal exited with code ${code}; see the PublicLocal output`);
    else if (code && code !== 0) vscode.window.showWarningMessage(`PublicLocal stopped (code ${code}). See the PublicLocal output.`);
    link = inspector = "";
    idle();
  });
}

function failed(msg: string) {
  proc = undefined;
  idle();
  out.show(true);
  vscode.window.showErrorMessage(`PublicLocal: ${msg.trim().split("\n").pop()}`);
}

async function notInstalled(bin: string) {
  proc = undefined;
  idle();
  const isWin = process.platform === "win32";
  const cmd = isWin ? "irm https://publiclocal.app/install.ps1 | iex" : "curl -fsSL https://publiclocal.app/install.sh | sh";
  const a = await vscode.window.showErrorMessage(`The "${bin}" client is not installed.`, "Install in terminal", "Open docs");
  if (a === "Install in terminal") {
    const t = vscode.window.createTerminal("PublicLocal install");
    t.show();
    t.sendText(cmd);
  } else if (a === "Open docs") {
    vscode.env.openExternal(vscode.Uri.parse("https://publiclocal.app/#install"));
  }
}

function stop() {
  if (!proc) return;
  const p = proc;
  proc = undefined;
  p.kill();
  out.appendLine("Stopped.");
  link = inspector = "";
  idle();
}

// splitArgs splits a flag string the way a shell would for simple quoting.
function splitArgs(s: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(s))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}
