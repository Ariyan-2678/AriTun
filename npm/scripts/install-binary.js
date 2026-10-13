#!/usr/bin/env node
// Download the AriTun binary for this platform from GitHub Releases.
// Used as "postinstall" by both aritun-client and aritun-server.
//
// Reads from env:
//   ARITUN_BIN_NAME   required — "aritun" or "aritund"
//   ARITUN_VERSION    package version (npm_package_version fallback)
//   ARITUN_GITHUB_REPO  optional, default "Ariyan-2678/AriTun"

"use strict";

const fs = require("fs");
const path = require("path");
const https = require("https");
const { execFileSync } = require("child_process");

const BIN_NAME = process.env.ARITUN_BIN_NAME;
if (!BIN_NAME) {
  console.error("aritun-install: ARITUN_BIN_NAME not set");
  process.exit(1);
}

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
    process.exit(1);
  }
  return { os, arch };
}

function assetName(os, arch) {
  // release asset: aritun-linux-amd64.tar.gz / aritun-windows-amd64.zip
  const base = `${BIN_NAME}-${os}-${arch}`;
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

  // extract
  if (os === "windows") {
    // PowerShell Expand-Archive
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

  // chmod +x on unix
  if (os !== "windows") {
    const binPath = path.join(vendorDir, BIN_NAME);
    fs.chmodSync(binPath, 0o755);
  }

  console.log(`aritun-install: installed ${BIN_NAME} ${VERSION} (${os}/${arch})`);
}

main().catch((err) => {
  console.error("aritun-install: failed —", err.message);
  process.exit(1);
});
