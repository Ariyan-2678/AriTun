#!/usr/bin/env node
// Download the AriTun server binary for this platform from GitHub Releases.
"use strict";

const fs = require("fs");
const path = require("path");
const https = require("https");
const { execFileSync } = require("child_process");

const BIN_NAME = "aritund";
// GitHub Release asset prefix — matches the npm package name so the release
// page is unambiguous (aritun-client-… = client, aritun-server-… = server).
const ASSET_PREFIX = "aritun-server";
const VERSION = (
  process.env.ARITUN_VERSION ||
  process.env.npm_package_version ||
  "0.1.0"
).replace(/^v/, "");
const REPO = process.env.ARITUN_GITHUB_REPO || "Ariyan-2678/AriTun";

function platformTriple() {
  const osMap = { win32: "windows", linux: "linux", darwin: "darwin" };
  const archMap = { x64: "amd64", arm64: "arm64" };
  const os = osMap[process.platform];
  const arch = archMap[process.arch];
  if (!os || !arch) {
    console.error(
      `aritun-install: unsupported platform ${process.platform}/${process.arch}`
    );
    process.exit(0); // don't fail install on exotic platforms
  }
  return { os, arch };
}

function assetName(os, arch) {
  const base = `${ASSET_PREFIX}-${os}-${arch}`;
  return os === "windows" ? `${base}.zip` : `${base}.tar.gz`;
}

function download(url, dest, redirects = 5) {
  return new Promise((resolve, reject) => {
    if (redirects <= 0) return reject(new Error("too many redirects"));
    https
      .get(url, (res) => {
        if (
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location
        ) {
          res.resume();
          return resolve(
            download(new URL(res.headers.location, url).href, dest, redirects - 1)
          );
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(
            new Error(`GET ${url} -> ${res.statusCode} ${res.statusMessage}`)
          );
        }
        const file = fs.createWriteStream(dest);
        res.pipe(file);
        file.on("finish", () => file.close(() => resolve(dest)));
        file.on("error", reject);
      })
      .on("error", reject);
  });
}

async function main() {
  const { os, arch } = platformTriple();
  const asset = assetName(os, arch);
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${asset}`;
  const vendorDir = path.join(__dirname, "vendor");
  fs.mkdirSync(vendorDir, { recursive: true });

  const archivePath = path.join(vendorDir, asset);
  console.log(`aritun-install: downloading ${url}`);
  await download(url, archivePath);

  if (os === "windows") {
    execFileSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-Command",
        `Expand-Archive -Path "${archivePath}" -DestinationPath "${vendorDir}" -Force`,
      ],
      { stdio: "inherit" }
    );
  } else {
    execFileSync("tar", ["-xzf", archivePath, "-C", vendorDir], {
      stdio: "inherit",
    });
  }
  fs.unlinkSync(archivePath);

  // archive contains e.g. aritund-windows-amd64.exe → rename to aritund.exe
  const extracted = path.join(vendorDir, `${BIN_NAME}-${os}-${arch}${os === "windows" ? ".exe" : ""}`);
  const target = path.join(vendorDir, os === "windows" ? `${BIN_NAME}.exe` : BIN_NAME);
  if (fs.existsSync(extracted)) {
    fs.renameSync(extracted, target);
  }
  if (os !== "windows") {
    fs.chmodSync(target, 0o755);
  }

  console.log(`aritun-install: installed ${BIN_NAME} ${VERSION} (${os}/${arch})`);
}

main().catch((err) => {
  console.error("aritun-install: failed —", err.message);
  process.exit(1);
});
