## Silent auto-update from GitHub releases.
##
## On launch, fork a detached worker (`payf --self-update-check`) that
## polls the GitHub releases API, downloads the matching archive, and
## atomically swaps the running binary's path. The current process keeps
## the old inode; the next launch picks up the new one. Throttled to one
## API hit per 4h.
##
## Off by default: source builds (`nimble install`) must not quietly
## replace what the user just built. CI passes `-d:autoUpdate` for
## prebuilt release binaries. Either way `PAYF_AUTO_UPDATE=true|false`
## (handy in payf's .env) wins.

import std/[httpclient, json, os, parseutils, strutils, times]

# Same strdefine payf.nim declares; -d:NimblePkgVersion=… sets both.
const NimblePkgVersion {.strdefine.} = "dev"

const autoUpdate {.booldefine.} = false

const
  Repo = "capocasa/payf"
  ThrottleSecs = 4 * 60 * 60

const Archive =
  when defined(linux) and (defined(amd64) or defined(x86_64)):
    "payf-linux-amd64.tar.gz"
  elif defined(linux) and (defined(arm64) or defined(aarch64)):
    "payf-linux-arm64.tar.gz"
  elif defined(macosx):
    "payf-macos-universal.tar.gz"
  elif defined(windows) and (defined(amd64) or defined(x86_64)):
    "payf-windows-amd64.zip"
  else:
    ""  # unsupported platform - no auto-update

const BinName =
  when defined(windows): "payf.exe"
  else: "payf"

proc autoUpdateEnabled*(): bool =
  let v = getEnv("PAYF_AUTO_UPDATE").strip.toLowerAscii
  if v in ["true", "yes", "on", "1"]: return true
  if v in ["false", "no", "off", "0"]: return false
  autoUpdate

proc dataDir(): string =
  getEnv("XDG_DATA_HOME", getHomeDir() / ".local" / "share") / "payf"

proc lastVersionMarker(): string = dataDir() / "last-version"
proc updateCheckMarker(): string = dataDir() / "last-update-check"

proc parseSemver*(s: string): seq[int] =
  var t = s.strip
  if t.len > 0 and t[0] == 'v': t = t[1 .. ^1]
  for part in t.split('.'):
    var n = 0
    discard parseutils.parseInt(part, n, 0)
    result.add n

proc semverGt*(a, b: string): bool =
  let pa = parseSemver(a)
  let pb = parseSemver(b)
  for i in 0 ..< max(pa.len, pb.len):
    let av = if i < pa.len: pa[i] else: 0
    let bv = if i < pb.len: pb[i] else: 0
    if av != bv: return av > bv
  false

proc throttleExpired(): bool =
  let path = updateCheckMarker()
  if not fileExists(path): return true
  try:
    let ts = readFile(path).strip.parseFloat
    return epochTime() - ts > ThrottleSecs.float
  except CatchableError:
    return true

proc touchThrottle() =
  try:
    createDir(dataDir())
    writeFile(updateCheckMarker(), $epochTime())
  except CatchableError: discard

proc fetchLatestTag(): string =
  try:
    let client = newHttpClient(timeout = 10_000, userAgent = "payf-update")
    defer: client.close()
    let resp = client.get("https://api.github.com/repos/" & Repo & "/releases/latest")
    if resp.code.int div 100 != 2: return ""
    parseJson(resp.body){"tag_name"}.getStr("")
  except CatchableError:
    ""

proc downloadAsset(tag, asset, dest: string): bool =
  let url = "https://github.com/" & Repo & "/releases/download/" & tag & "/" & asset
  try:
    let client = newHttpClient(timeout = 60_000, userAgent = "payf-update")
    defer: client.close()
    let resp = client.get(url)
    if resp.code.int div 100 != 2: return false
    writeFile(dest, resp.body)
    fileExists(dest) and getFileSize(dest) > 0
  except CatchableError:
    false

proc extractArchive(archive, workDir: string): string =
  ## Extract `archive` into `workDir` (wiped first); return the dir
  ## holding the binary, or "". `tar -xf` autodetects gzip and zip
  ## (bsdtar ships with Windows 10+).
  try: removeDir(workDir) except CatchableError: discard
  try: createDir(workDir) except CatchableError: return ""
  let flag = when defined(windows): "-xf" else: "-xzf"
  if execShellCmd("tar " & flag & " " & quoteShell(archive) & " -C " &
                  quoteShell(workDir)) != 0:
    return ""
  for f in walkDirRec(workDir):
    if f.extractFilename == BinName:
      return parentDir(f)
  ""

proc swapInstall*(srcDir, destBin: string): bool =
  ## Replace `destBin` with the new binary from `srcDir`. README/LICENSE
  ## bundle docs are skipped.
  ##
  ## POSIX: stage as `<dest>.new`, atomic rename; the running process
  ## keeps the old inode. Windows: rename the in-use file to `.old`
  ## first (rename of an open file is allowed, overwrite is not);
  ## `.old` files are cleaned up on the next launch.
  let destDir = parentDir(destBin)
  for entry in walkDir(srcDir):
    if entry.kind notin {pcFile, pcLinkToFile}: continue
    let name = entry.path.extractFilename
    if name in ["README.md", "LICENSE"]: continue
    let dest = destDir / name
    when defined(windows):
      if fileExists(dest):
        let stale = dest & ".old"
        try: removeFile(stale) except CatchableError: discard
        try: moveFile(dest, stale) except CatchableError: discard
      try: copyFile(entry.path, dest)
      except CatchableError: return false
    else:
      let stage = dest & ".new"
      try:
        copyFile(entry.path, stage)
        if name == BinName:
          setFilePermissions(stage, {fpUserRead, fpUserWrite, fpUserExec,
                                     fpGroupRead, fpGroupExec,
                                     fpOthersRead, fpOthersExec})
        moveFile(stage, dest)
      except CatchableError:
        try: removeFile(stage) except CatchableError: discard
        return false
  true

proc cleanupStaleBinaries*() =
  when defined(windows):
    let dir = parentDir(getAppFilename())
    for f in walkDir(dir):
      if f.kind == pcFile and f.path.endsWith(".old"):
        try: removeFile(f.path) except CatchableError: discard

proc selfUpdateCheck*(curVersion = NimblePkgVersion, targetPath = "",
                      force = false) =
  ## Worker entry point. Runs detached and strictly silent.
  ## `curVersion`/`targetPath`/`force` exist for tests.
  if not force and not autoUpdateEnabled(): return
  if Archive.len == 0: return
  let latest = fetchLatestTag()
  if latest.len == 0: return
  if not semverGt(latest, curVersion): return
  let cache = dataDir() / "update"
  try: createDir(cache) except CatchableError: return
  let archivePath = cache / Archive
  if not downloadAsset(latest, Archive, archivePath): return
  let srcDir = extractArchive(archivePath, cache / "extract")
  if srcDir.len == 0: return
  let dest = if targetPath.len > 0: targetPath else: getAppFilename()
  discard swapInstall(srcDir, dest)
  try: removeFile(archivePath) except CatchableError: discard
  try: removeDir(cache / "extract") except CatchableError: discard

proc showUpdateNoticeMaybe*() =
  ## One dim stderr line on the first launch after a swap.
  let marker = lastVersionMarker()
  var prev = ""
  if fileExists(marker):
    try: prev = readFile(marker).strip
    except CatchableError: discard
  if prev.len > 0 and prev != NimblePkgVersion:
    try: stderr.writeLine "  - payf updated to " & NimblePkgVersion
    except CatchableError: discard
  if prev != NimblePkgVersion:
    try:
      createDir(dataDir())
      writeFile(marker, NimblePkgVersion)
    except CatchableError: discard

when defined(posix):
  import std/posix

  proc spawnBackgroundUpdateMaybe*() =
    ## Double-fork + setsid so the worker survives the parent exiting
    ## and SIGHUP from the terminal. Throttle is claimed before the
    ## fork so concurrent launches don't pile up.
    if not autoUpdateEnabled() or Archive.len == 0: return
    if not throttleExpired(): return
    touchThrottle()
    let pid = posix.fork()
    if pid < 0: return
    if pid > 0:
      var status: cint
      discard posix.waitpid(pid, status, 0)
      return
    discard posix.setsid()
    let pid2 = posix.fork()
    if pid2 < 0: quit(1)
    if pid2 > 0: quit(0)
    let fd = posix.open("/dev/null", O_RDWR)
    if fd >= 0:
      discard posix.dup2(fd, 0)
      discard posix.dup2(fd, 1)
      discard posix.dup2(fd, 2)
      if fd > 2: discard posix.close(fd)
    let exe = getAppFilename()
    let argv = allocCStringArray([exe, "--self-update-check"])
    discard posix.execv(exe.cstring, argv)
    quit(1)
elif defined(windows):
  import std/osproc

  proc spawnBackgroundUpdateMaybe*() =
    if not autoUpdateEnabled() or Archive.len == 0: return
    if not throttleExpired(): return
    touchThrottle()
    try:
      let p = startProcess(getAppFilename(), args = ["--self-update-check"],
                           options = {poDaemon})
      p.close()
    except OSError: discard
else:
  proc spawnBackgroundUpdateMaybe*() = discard
