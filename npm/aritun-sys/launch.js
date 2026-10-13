#!/usr/bin/env node
// Cross-platform launcher that finds the downloaded AriTun binary and execs it.
"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const BIN_NAME = process.env.ARITUN_BIN_NAME;
if (!BIN_NAME) {
  console.error("aritun-launch: ARITUN_BIN_NAME not set");
  process.exit(1);
}

const osMap = { win32: "windows", linux: "linux", darwin: "darwin" };
const archMap = { x64: "amd64", arm64: "arm64" };
const os = osMap[process.platform];
const arch = archMap[process.arch];

if (!os || !arch) {
  console.error(
    `aritun-launch: unsupported platform ${process.platform}/${process.arch}`
  );
  process.exit(1);
}

const binPath = path.join(
  __dirname,
  "vendor",
  os === "windows" ? `${BIN_NAME}.exe` : BIN_NAME
);

if (!fs.existsSync(binPath)) {
  console.error(
    `aritun-launch: binary not found at ${binPath}\n` +
      `Run: npm rebuild ${process.env.npm_package_name || "aritun-sys"}`
  );
  process.exit(1);
}

const result = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });
process.exit(result.status === null ? 1 : result.status);
