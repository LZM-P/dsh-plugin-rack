/**
 * Host half of the plugin dashboard.
 *
 * It owns every operation and serves one small same-origin JSON API that the
 * Client panel calls. Keeping the operations here (instead of in the Client)
 * means the UI and any future agent tool share a single implementation, and it
 * avoids depending on the Client-side Remote access policy for `pluginManager`.
 *
 *   GET  /api/dsh-plugin-rack/            alias of /ping, so a bare URL answers
 *   GET  /api/dsh-plugin-rack/ping        liveness, touches no service
 *   GET  /api/dsh-plugin-rack/state       every plugin row + the roster
 *   GET  /api/dsh-plugin-rack/detail      ?entryId=  one row + its package.json
 *   GET  /api/dsh-plugin-rack/updates     check every exact-pinned dep against its registry
 *   POST /api/dsh-plugin-rack/updates     { names: [...] }  install those exact versions
 *   GET  /api/dsh-plugin-rack/extras      deps that are not exact versions (link / github / tarball / file)
 *   POST /api/dsh-plugin-rack/extras      { name, action: 'repull' | 'pin' | 'file-upgrade' }
 *   GET  /api/dsh-plugin-rack/updatelog   the last update attempt, as written to disk
 *   GET  /api/dsh-plugin-rack/registries  the registry the host resolves + whether GITHUB_TOKEN is set
 *   GET  /api/dsh-plugin-rack/removable   bundles the host will let us uninstall
 *   GET  /api/dsh-plugin-rack/inspect     ?spec=  preview only, installs nothing
 *   GET  /api/dsh-plugin-rack/fileplan    ?name=  what a local `file:` dep would upgrade to
 *   POST /api/dsh-plugin-rack/install     { spec }  through pluginManager.installBundle
 *   POST /api/dsh-plugin-rack/uninstall   { name }  through pluginManager.removeBundle
 *   POST /api/dsh-plugin-rack/plugin      { entryId, enabled?, auto? }
 *   POST /api/dsh-plugin-rack/bundle      { name, enabled }  compose or drop a bundle layer
 *   POST /api/dsh-plugin-rack/bulk        { enabled, scope?, save?, cancel? }
 *   POST /api/dsh-plugin-rack/roster      { mode: 'group', scope, auto }
 *   GET  /api/dsh-plugin-rack/skills      every skill root, scanned, with its on/off state
 *   POST /api/dsh-plugin-rack/skills/toggle  { name, enabled }  switch one skill on or off
 *   POST /api/dsh-plugin-rack/skills/note    { name, note }     annotate one skill
 *   GET  /api/dsh-plugin-rack/summary     read-only rows for scripts and future agent tools
 *   GET  /api/dsh-plugin-rack/job         the install running now, or the last one that finished
 *   POST /api/dsh-plugin-rack/job         { action: 'cancel' }  stop the run that is executing now
 *
 * Bodies must be `application/json` (anything else answers 415), a known path
 * with the wrong verb answers 405, and only one write operation runs at a time
 * (install / uninstall / update / extras / bulk share one mutex), because two
 * pnpm runs editing the same package.json + pnpm-lock.yaml can interleave into
 * a profile that installs nothing.
 *
 * Every request must pass two gates before any of the above runs: the Host
 * header has to name a loopback interface (127.0.0.1 / localhost / ::1), and
 * if an Origin header is present it has to resolve to the same loopback set.
 * Together they stop a malicious web page in the user's browser from driving
 * the API — the web server itself only listens on loopback, so the only
 * attack surface left is a same-machine browser tab.
 *
 * A bulk action always skips this plugin's own row: disabling it would tear
 * down the very route answering the request. Core components are NOT skipped as
 * a group — only 16 of the 204 @deepseek-ai/* rows are genuinely read-only, so
 * `manageable` is the real gate, and the roster plus `scope` decide the rest.
 *
 * Enable/disable normally goes through the shipped `pluginManager` service. The
 * one deliberate exception is `bulk` with `save: true`, which writes the
 * profile's cordis.patch.yml itself — atomically, comments preserved, and only
 * overrides this plugin created are ever removed — so the user can switch
 * plugins off and restart once instead of waiting for a reload per plugin.
 */
import { appendFileSync, copyFileSync, createWriteStream, existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs'

import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { homedir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect as netConnect } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { createRequire } from 'node:module'
import { EXACT_VERSION, compareVersions, isVersionSpec, parseSpec, satisfiesSpec } from './lib/spec.js'
import {
  applySkillState,
  createSkillPolicyProvider,
  pluginSkillPackages,
  readSkillState,
  resolveWinners,
  scanSkills,
  skillRoots,
  writeSkillState,
} from './lib/skills.js'

const ROUTE_PREFIX = '/api/dsh-plugin-rack'
const require = createRequire(import.meta.url)
// Read from package.json instead of a literal: the panel reports this number to
// the user and to the update checker, and a hand-maintained copy drifted from
// the published version the first time it mattered.
const VERSION = require('./package.json').version
// The package was called dsh-plugin-dashboard before the public release. Keep
// the old name recognised so a half-migrated install still treats the panel as
// itself — otherwise "turn everything off" would switch off the very route
// answering that request.
const SELF = 'dsh-plugin-rack'
const SELF_NAMES = [SELF, 'dsh-plugin-dashboard']

/** Known routes and their verbs, so a wrong verb answers 405 instead of 404. */
const ROUTES = {
  '/': ['GET'],
  '/ping': ['GET'],
  '/state': ['GET'],
  '/detail': ['GET'],
  '/updates': ['GET', 'POST'],
  '/extras': ['GET', 'POST'],
  '/updatelog': ['GET'],
  '/registries': ['GET'],
  '/removable': ['GET'],
  '/inspect': ['GET'],
  '/fileplan': ['GET'],
  '/install': ['POST'],
  '/uninstall': ['POST'],
  '/plugin': ['POST'],
  '/bulk': ['POST'],
  '/roster': ['POST'],
  // 技能：本插件自己扫、自己存开关，不经过别的插件。
  '/skills': ['GET'],
  '/skills/toggle': ['POST'],
  '/skills/note': ['POST'],
  // 只读摘要，给脚本和未来的 agent tool 用。写操作刻意不暴露在这里——
  // 让一个语言模型替人点「确认卸载」不是个好主意，那种通道要单独的权限设计。
  '/summary': ['GET'],
  // 后台更新任务：面板关掉之后 pnpm 还在跑，重新打开时用它把进度接回来。
  '/job': ['GET', 'POST'],
}

export const name = 'plugin-rack'
export const inject = ['webServer', 'pluginManager']

/** @type {{version: number, seeded: boolean, auto: string[], created: string[]} | null} */
let rosterState = null
let storageMode = 'file'
let profileStateKey = null

function stateBase() {
  const configured = typeof process.env.DSH_HOME === 'string' ? process.env.DSH_HOME.trim() : ''
  const home = configured.length > 0 ? configured : join(homedir(), '.dsh')
  return join(home, 'plugin-rack')
}

/**
 * Where this profile keeps its roster, job and queue.
 *
 * One shared file meant the 自动 list of one profile drove the one-click buttons
 * of another — the single most confusing way for a plugin manager to be wrong.
 * The directory is keyed by the profile it belongs to; before apply() learns the
 * profile, the old single directory is still used so nothing reads a half-set
 * path.
 */
function stateDir() {
  return profileStateKey === null ? stateBase() : join(stateBase(), 'profiles', profileStateKey)
}


/**
 * Adopt the state a previous build left behind.
 *
 * A renamed plugin ships a new state directory (`<home>/plugin-rack/profiles/<key>`
 * instead of the old name's), so a user who upgrades to it would otherwise boot
 * into an empty panel: their auto roster, their queued update, their running job
 * (and the fact it finished), their download proxy, and the history of past runs
 * would all look gone.
 *
 * Copy is per-file and non-destructive: the old files are left in place, so a
 * machine that runs two profiles against an upgraded build still has one copy of
 * the shared history to fall back on. Existence wins over the legacy copy — a
 * file already in the profile directory is newer by definition.
 *
 * The whole directory is copied rather than a list of known file names: a state
 * file added in a later version then migrates too, instead of being silently
 * left behind by a list nobody remembered to update.
 */
function adoptProfile(ctx) {
  let dir = null
  try {
    const facts = profileFacts(ctx)
    dir = facts === null ? null : facts.dir
  } catch {
    dir = null
  }
  if (typeof dir !== 'string' || dir === '') return
  const key = basename(dir).replace(/[^A-Za-z0-9._-]+/g, '-')
  if (key === '' || key === '.' || key === '..') return
  profileStateKey = key
  // 整目录搬，不再维护一份「已知文件」清单：将来新增的状态文件也跟着走。
  let entries = []
  try {
    entries = readdirSync(stateBase(), { withFileTypes: true })
  } catch {
    // 旧目录不存在＝没什么可迁的（新装用户就是这种情况）。
    entries = []
  }
  for (const entry of entries) {
    if (entry.isFile() !== true) continue
    const name = entry.name
    if (name === '' || name === '.' || name === '..') continue
    try {
      const target = join(stateDir(), name)
      // Only ever fill a gap: a file that already exists in the profile's own
      // directory is newer than the shared copy by definition.
      if (existsSync(target)) continue
      mkdirSync(stateDir(), { recursive: true })
      copyFileSync(join(stateBase(), name), target)
    } catch {
      // Losing one carry-over file is survivable: the roster reseeds, the job
      // page reports "no run", the queue starts empty and the proxy falls back
      // to the environment. Losing the whole migration is survivable too.
    }
  }
}

function stateFile() {
  return join(stateDir(), 'state.json')
}

/**
 * One scan of every skill root, already resolved against the rack's own on/off
 * list, so the panel renders straight from it.
 *
 * @param {object} ctx
 * @returns {{ ok: true, roots: Array<object>, skills: Array<object>, summary: object, statePath: string }}
 */
async function skillSnapshot(ctx) {
  const state = readSkillState(stateDir())
  const roots = skillRoots({
    projectRoots: projectRootsOf(ctx),
    pluginRoots: pluginSkillPackages(await nodeModulesRootOf(ctx)),
  })
  const scanned = scanSkills(roots)
  const resolved = resolveWinners(scanned.skills)
  const skills = applySkillState(resolved, state)
  const byRoot = new Map()
  for (const root of scanned.roots) byRoot.set(root.key, { ...root, skills: [] })
  for (const skill of skills) {
    const bucket = byRoot.get(skill.rootKey)
    if (bucket !== undefined) bucket.skills.push(skill)
  }
  for (const bucket of byRoot.values()) {
    bucket.skills.sort((a, b) => a.name.localeCompare(b.name))
  }
  const list = [...byRoot.values()].filter((root) => root.exists || root.skills.length > 0)
  return {
    ok: true,
    roots: list,
    skills,
    summary: {
      total: skills.length,
      enabled: skills.filter((skill) => skill.enabled === true).length,
      disabled: skills.filter((skill) => skill.enabled !== true && skill.loadable === true).length,
      broken: skills.filter((skill) => skill.loadable !== true).length,
      shadowed: skills.filter((skill) => skill.shadowedBy !== undefined).length,
    },
    statePath: join(stateDir(), 'skills.json'),
  }
}

/**
 * Working directories whose project skill roots should be scanned. Uses the
 * registered workspaces when available and degrades to the process cwd.
 *
 * @param {object} ctx
 * @returns {string[]}
 */
function projectRootsOf(ctx) {
  const roots = new Set()
  try {
    const registry = typeof ctx.get === 'function' ? ctx.get('workspaceRegistry') : undefined
    const list = registry !== undefined && typeof registry.list === 'function' ? registry.list() : []
    for (const workspace of Array.isArray(list) ? list : []) {
      const dir = workspace?.root ?? workspace?.path
      if (typeof dir === 'string' && dir !== '') roots.add(resolve(dir))
    }
  } catch {
    // A missing registry only costs project-local skills, not the user's ones.
  }
  if (roots.size === 0) {
    try {
      roots.add(resolve(process.cwd()))
    } catch {
      // No cwd at all: user roots still work.
    }
  }
  return [...roots]
}

/**
 * Turn one skill on or off in the rack's own state file.
 *
 * @param {object} ctx
 * @param {string} name
 * @param {boolean} enabled
 * @returns {{ ok: true, disabled: string[] }}
 */
function setSkillEnabled(ctx, name, enabled) {
  if (typeof name !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name)) {
    throw new HttpError(400, 'invalid skill name')
  }
  const state = readSkillState(stateDir())
  const next = new Set(state.disabled)
  if (enabled) next.delete(name)
  else next.add(name)
  const disabled = [...next].sort()
  writeSkillState(stateDir(), { disabled, notes: state.notes })
  return { ok: true, disabled }
}

/**
 * Save the note shown next to one skill. Empty string clears it.
 *
 * @param {object} ctx
 * @param {string} name
 * @param {string} note
 * @returns {{ ok: true, notes: Record<string, string> }}
 */
function setSkillNote(ctx, name, note) {
  if (typeof name !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name)) {
    throw new HttpError(400, 'invalid skill name')
  }
  const state = readSkillState(stateDir())
  const notes = { ...state.notes }
  const text = typeof note === 'string' ? note.trim().slice(0, 500) : ''
  if (text === '') delete notes[name]
  else notes[name] = text
  writeSkillState(stateDir(), { disabled: state.disabled, notes })
  return { ok: true, notes }
}

/** Where the last update run is recorded, so a closed panel can pick it back up. */
function jobFile() {
  return join(stateDir(), 'job.json')
}

/**
 * Updates the host already fetched but could not install yet, because an Agent
 * was mid-turn. The verified tarball sits on disk, so applying a queued entry
 * later costs one `pnpm install` — no download, no waiting on GitHub again.
 */
function queueFile() {
  return join(stateDir(), 'queue.json')
}

function readQueue() {
  try {
    const parsed = JSON.parse(readFileSync(queueFile(), 'utf8'))
    if (Array.isArray(parsed)) {
      return parsed.filter(item => item !== null && typeof item === 'object' && typeof item.kind === 'string')
    }
  } catch (error) {
    void error
  }
  return []
}

function writeQueue(list) {
  try {
    mkdirSync(stateDir(), { recursive: true })
    writeFileSync(queueFile(), JSON.stringify(list, null, 2) + '\n', 'utf8')
  } catch {
    // Losing a queued entry only costs the user another click.
  }
}

function queueKey(item) {
  if (item.kind === 'updates') return 'updates:' + (Array.isArray(item.names) ? item.names.join(',') : '')
  return 'extras:' + String(item.name ?? '')
}

function enqueueItem(item) {
  const list = readQueue().filter(one => queueKey(one) !== queueKey(item))
  list.push({ ...item, queuedAt: new Date().toISOString() })
  writeQueue(list)
  return list
}

function dequeueItem(item) {
  writeQueue(readQueue().filter(one => queueKey(one) !== queueKey(item)))
}

/** The run this host process is executing right now, if any. */
let activeJob = null
/** Aborts the network work of the run in `activeJob` when the user cancels it. */
let activeJobAbort = null
/** Which step the run in `activeJob` is on: 'start', 'download' or 'install'. */
let activeJobStage = null
/** The pnpm child of the run in `activeJob`, so cancel can actually stop it. */
let activePnpmChild = null

function readJob() {
  try {
    const parsed = JSON.parse(readFileSync(jobFile(), 'utf8'))
    if (parsed !== null && typeof parsed === 'object' && typeof parsed.id === 'string') return parsed
  } catch (error) {
    // 没有 job.json 就是还没更新过；坏文件当没有，下次写入会重建成好的。
    void error
  }
  return null
}

function persistJob(job) {
  try {
    mkdirSync(stateDir(), { recursive: true })
    writeFileSync(jobFile(), JSON.stringify(job, null, 2) + '\n', 'utf8')
  } catch {
    // 只读的 home 也能跑完这次更新，只是下次打开面板接不到它。
  }
}

/**
 * 登记一次装包任务。更新可能要跑 25 分钟，浏览器这时候完全可能被关掉，
 * 所以任务的状态必须活在宿主里，而不是活在发起它的那个请求里。
 */
function beginJob(kind, names) {
  const job = {
    id: Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8),
    kind,
    names: Array.isArray(names) ? names.filter(one => typeof one === 'string') : [],
    startedAt: new Date().toISOString(),
    finishedAt: null,
    ok: null,
    message: null,
    restart: false,
    updated: [],
    failed: [],
    // 这一轮真正递给 pnpm 的那几个包。批量更新是一轮一轮跑的，面板靠它把
    // 「正在转」的标记推到当前这一轮的包上，而不是整批都挂着同一个圈。
    installing: [],
  }
  activeJob = job
  activeJobAbort = new AbortController()
  activeJobStage = 'start'
  persistJob(job)
  return job
}

function endJob(job, result) {
  const previousMessage = job.message
  job.finishedAt = new Date().toISOString()
  job.ok = result !== null && typeof result === 'object' && result.ok === true
  job.message = result !== null && typeof result === 'object' && typeof result.message === 'string' ? result.message : null
  // A cancelled run keeps saying so even when the dying pnpm reports its own
  // failure a moment later.
  if (job.cancelled === true && job.ok !== true) job.message = previousMessage
  job.restart = result !== null && typeof result === 'object' && result.restart === true
  // 跑完了就没有「正在装」这一说了，留着会让最后一轮的行一直转圈。
  job.installing = []
  job.updated = result !== null && typeof result === 'object' && Array.isArray(result.updated) ? result.updated : []
  job.failed = result !== null && typeof result === 'object' && Array.isArray(result.failed) ? result.failed : []
  if (activeJob !== null && activeJob.id === job.id) {
    activeJob = null
    activeJobAbort = null
    activeJobStage = null
    activePnpmChild = null
  }
  persistJob(job)
  return job
}

/**
 * 取消正在跑的任务。下载阶段的 fetch 会立刻中断；pnpm 已经起来的那种先杀掉进程树，
 * 由失败分支回滚。回滚本身还是一次 pnpm 运行，所以任务在回滚完成前保持 running——
 * 否则界面显示「已取消」，后台却还在改 node_modules，用户既看不见也停不下。
 */
function cancelJob() {
  const job = activeJob
  if (job === null) return { ok: false, message: 'no update is running' }
  // 回滚本身也是一次 pnpm 运行（install 重同步）。这时候再点取消会把它杀掉，
  // 留下半同步的 node_modules —— 比不回滚更糟。回滚必须跑完。
  if (job.stage === 'rollback') {
    return { ok: true, job: jobStatus() }
  }
  job.cancelled = true
  const killedPnpm = activePnpmChild !== null
  if (activePnpmChild !== null) {
    killTree(activePnpmChild)
    activePnpmChild = null
  }
  // 先 abort 再决定是否 endJob：abort 必须在任何可能把 activeJobAbort 置空的
  // 路径之前发生，否则还在跑的 applyUpdates 读到 null 会以为什么都没发生。
  if (activeJobAbort !== null) activeJobAbort.abort(new Error('cancelled by the user'))
  if (killedPnpm) {
    // endJob runs from the failed install's rollback path; until then the job
    // stays visible, with the cancel button gone and this message on screen.
    job.stage = 'rollback'
    job.message = '已取消：pnpm 进程被终止，正在回滚改动'
    persistJob(job)
    return { ok: true, job: jobStatus() }
  }
  const message = activeJobStage === 'download' ? '已取消：下载已中断，下好的部分留着下次续传' : '已取消'
  endJob(job, { ok: false, message })
  return { ok: true, job: jobStatus() }
}

/** 这个任务是否已被取消。job 对象是取消事实的唯一来源，全局量只是它的镜像。 */
function jobCancelled(job) {
  return job !== null && job !== undefined && job.cancelled === true
}

/** 取消检查：任务被取消，或它自己的 abort 信号已触发，都算。 */
function assertNotCancelled(job) {
  if (jobCancelled(job)) throw new Error('cancelled by the user')
  if (activeJobAbort !== null && activeJobAbort.signal.aborted) throw new Error('cancelled by the user')
}

/**
 * 给结果挂上「这次没有维护门」的事实。
 *
 * applyUpdates 有自己的 unguarded 处理；applyExtras / applyFileUpgrade 这些
 * 走另一条路的入口也必须说同一句话，否则同一台机器上「批量更新会告诉你没等空闲、
 * 单装一个却不说」—— 用户没法判断哪次是安全的。
 */
function markUnguarded(result, unguarded) {
  if (unguarded !== true) return result
  if (result === null || typeof result !== 'object') return result
  return Object.assign({}, result, {
    unguarded: true,
    message:
      typeof result.message === 'string' && result.message.length > 0
        ? result.message + '（宿主没有 agents 服务：这次没等会话空闲就改了 node_modules）'
        : '宿主没有 agents 服务：这次没等会话空闲就改了 node_modules',
  })
}

/** 正在跑的任务，或上一次的结果；finishedAt 为空但已不在跑 = 被宿主重启掐断了。 */
function jobStatus() {
  const job = activeJob !== null ? activeJob : readJob()
  if (job === null) return null
  const running = activeJob !== null && activeJob.id === job.id
  // 回滚期间不接受取消：那是唯一一段「后台必须跑完」的工作。
  const cancelable = running && job.stage !== 'rollback'
  return Object.assign({}, job, {
    running,
    cancelable,
    // Which step the host is on right now. Without it the panel can only say
    // "updating", which looks frozen during the (up to three minute) wait for
    // every session to go idle.
    phase: running ? activeJobStage : null,
    interrupted: !running && job.finishedAt === null,
  })
}

function emptyRoster() {
  // `removed` 是「用户亲手取消过」的名单。没有它就无法区分「还没决定」和
  // 「决定不要」——每次刷新把没勾的补回来，用户就永远取消不掉勾选。
  // `auto`    = 「自动/手动」：一键开启/关闭作用的名单
  // `update`  = 「参与一键更新」：更新页的勾选，和上面那份没有关系
  // 两份分开是因为它们是两件事：想让它参加批量开关，不等于想让它被自动升级。
  return { version: 1, seeded: false, auto: [], update: [], removed: [], created: [] }
}

function loadRoster() {
  try {
    const parsed = JSON.parse(readFileSync(stateFile(), 'utf8'))
    if (parsed !== null && typeof parsed === 'object' && Array.isArray(parsed.auto)) {
      return {
        state: {
          version: 1,
          seeded: parsed.seeded === true,
          auto: parsed.auto.filter(entry => typeof entry === 'string'),
          // Overrides this panel wrote into the profile patch. Only those may
          // be removed again; a pre-existing override belongs to the user.
          created: Array.isArray(parsed.created)
            ? parsed.created.filter(entry => typeof entry === 'string')
            : [],
        },
        storage: 'file',
      }
    }
  } catch (error) {
    // ENOENT means "first run"; anything else means unreadable or corrupt.
    // Both fall back to defaults, and the next write repairs the file.
    void error
  }
  return { state: emptyRoster(), storage: 'file' }
}

function roster() {
  if (rosterState === null) {
    const loaded = loadRoster()
    rosterState = loaded.state
    if (!Array.isArray(rosterState.removed)) rosterState.removed = []
    if (!Array.isArray(rosterState.update)) rosterState.update = []
    storageMode = loaded.storage
  }
  return rosterState
}

function persistRoster() {
  try {
    const file = stateFile()
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, `${JSON.stringify(rosterState, null, 2)}\n`, 'utf8')
    storageMode = 'file'
  } catch {
    // A read-only home still works for this session; the roster just lives in
    // memory and the client shows that in the footer.
    storageMode = 'memory'
  }
}

/** A readable label for a module name, shortening `file:///...` install specs. */
/**
 * Human-readable package name for a loader module specifier.
 *
 * A `file://` URL is a path inside some node_modules tree, so the package name
 * is the segment right after the LAST `node_modules/` — everything before that
 * is machine layout the user does not care about, and everything after it is
 * the package's own internal entry file. Taking the last two path segments
 * instead (the old behaviour) turned
 *   .../node_modules/cc-safety-net/dist/deepseek-harness/index.js
 * into `deepseek-harness/index.js`. That is not a package name, so the row was
 * listed under a name no user would recognise and did not sort with the rest.
 *
 * Scoped packages keep both segments (`@scope/name`). A path with no
 * node_modules segment at all falls back to the file stem.
 */
function displayName(moduleName) {
  if (!moduleName.startsWith('file://')) return moduleName
  const parts = moduleName.split('/').filter(Boolean)
  // Walk from the right so a nested node_modules (pnpm links one store into
  // every dependent) resolves to the package nearest the entry file.
  for (let index = parts.length - 2; index >= 0; index -= 1) {
    if (parts[index] !== 'node_modules') continue
    const first = parts[index + 1]
    if (first === undefined) break
    if (first.startsWith('@')) {
      const second = parts[index + 2]
      // `@scope` with nothing after it is a malformed path; fall through.
      if (second !== undefined && second.indexOf('.') !== 0) return `${first}/${second}`
      break
    }
    return first
  }
  const file = parts[parts.length - 1] ?? moduleName
  return file
}

/** The profile directory that owns `node_modules`, derived from a linked row. */
function profileDir(rows) {
  for (const row of rows) {
    if (!row.moduleName.startsWith('file://')) continue
    let dir = dirname(fileURLToPath(row.moduleName))
    for (let depth = 0; depth < 12; depth += 1) {
      if (basename(dir) === 'node_modules') return dirname(dir)
      const parent = dirname(dir)
      if (parent === dir) break
      dir = parent
    }
  }
  return null
}

function firstString(value) {
  return typeof value === 'string' && value.length > 0 ? value : null
}

/** One-minute memory: the skill page opens often and this walks the loader each time. */
const skillNodeModulesCache = { at: 0, value: null }

/**
 * The node_modules directory of the profile this panel is running in, or null.
 *
 * Plugin-bundled skills live there, so the skill scan needs the directory, not
 * just the rows. Only a linked row can be walked back to it; on a bare install
 * (no file:// module) there is nothing to derive from and null is honest.
 *
 * @param {object} ctx
 * @returns {Promise<string|null>}
 */
async function nodeModulesRootOf(ctx) {
  const cache = skillNodeModulesCache
  const now = Date.now()
  if (cache.value !== undefined && now - cache.at < 60_000) return cache.value
  /** @type {string|null} */
  let root = null
  try {
    // listPlugins() is async. Calling it without await yields a Promise, and
    // Array.isArray(Promise) is false — which silently produced "no packages"
    // and hid every bundled skill.
    const rows = ctx.pluginManager !== undefined && typeof ctx.pluginManager.listPlugins === 'function'
      ? await ctx.pluginManager.listPlugins()
      : null
    const named = Array.isArray(rows) ? rows.map(row => ({ moduleName: typeof row?.moduleName === 'string' ? row.moduleName : '' })) : []
    const dir = profileDir(named)
    root = dir === null ? null : join(dir, 'node_modules')
  } catch {
    root = null
  }
  skillNodeModulesCache.at = now
  skillNodeModulesCache.value = root
  return root
}

/** Longest subtitle we keep; the row already ellipsizes, this keeps the payload small. */
const BRIEF_MAX = 60

/** Short Chinese name for each installed plugin; keep these to a few characters. */
const ZH_ALIAS = {
  '@deepseek-ai/dsh-tool-subagent': '子智能体',
  'dsh-whale-widget': '余额挂件',
  'dsh-pocket': '手机访问',
  'dsh-m': '插件市场',
  dshmarket: '插件商城',
  '@tencent-connect/dsh-qqbot': 'QQ 机器人',
  '@linxin666/dsh-client-ui-git-graph': '提交图谱',
  '@linxin666/dsh-client-ui-task-board': '任务看板',
  'billion-context': '上下文压缩',
  'billion-context/dsh-compaction-gate': '压缩门控',
  'ds-bot/web-search': '机器人联网',
  '@vectorize-io/hindsight-coding-agents/dsh': '记忆编码智能体',
  'dsh-blender-mcp-bridge': 'Blender 桥接',
  'dsh-blender-plugin': 'Blender 直连',
  'dsh-univer-office': '办公套件',
  '@changfenhuang/dsh-genui': '内联 UI',
  'dsh-ops': 'Bash / Rust 工具',
  '@liustack/modlens': '视觉读图',
  '@michengai/dsh-archive-manager': '会话归档',
  '@michengai/dsh-skills-manager': '技能管理',
  '@nanmicoder/dsh-agent-teams': '多智能体',
  'dsh-our-free-model': '免费模型',
  'dsh-plugin-rack': '插件管理',
  'deepseek-harness/index.js': '命令安全网',
  'clearai-dsh': '智能体预设',
  'ds-bot': '机器人团队',
  'dsh-better-sidebar': '右侧边栏',
  'dsh-context': '上下文工具',
  'dsh-cost-meter': '费用计量',
  'dsh-ego-browser': 'Agent 浏览器',
  'dsh-free-search': '免费搜索',
  'dsh-pause-resume': '暂停 / 恢复',
  'dsh-unlag': '热重载',
  'lunheng-article-pipeline': '长文流水线',
}

/**
 * Short Chinese label for the harness' own components. The core plugins have
 * no manifest description, so without this the row would fall back to the raw
 * entry id. Matching is by longest prefix so a family like
 * `dsh-client-ui-settings-*` gets one label per family member.
 */
const CORE_ALIAS = [
  ['dsh-client-ui-settings-account', '账号设置'],
  ['dsh-client-ui-settings-agent-loop', '智能体循环设置'],
  ['dsh-client-ui-settings-general', '通用设置'],
  ['dsh-client-ui-settings-models', '模型设置'],
  ['dsh-client-ui-settings-plugin-inventory', '插件清单'],
  ['dsh-client-ui-settings-plugins', '插件设置'],
  ['dsh-client-ui-settings-session-log', '会话日志设置'],
  ['dsh-client-ui-settings-shell', '外壳设置'],
  ['dsh-client-ui-settings-subagent', '子智能体设置'],
  ['dsh-client-ui-settings-web-search', '联网搜索设置'],
  ['dsh-client-ui-agent-preset', '预设编辑器'],
  ['dsh-client-ui-approval', '审批界面'],
  ['dsh-client-ui-attachment', '附件'],
  ['dsh-client-ui-brand-official', '官方品牌'],
  ['dsh-client-ui-chat', '对话界面'],
  ['dsh-client-ui-commands', '命令面板'],
  ['dsh-client-ui-context-menu', '右键菜单'],
  ['dsh-client-ui-conversation', '会话列表'],
  ['dsh-client-ui-cordis', '插件内核'],
  ['dsh-client-ui-deliverables', '交付物'],
  ['dsh-client-ui-directory-picker-native', '目录选择'],
  ['dsh-client-ui-entry-customization', '入口定制'],
  ['dsh-client-ui-file-actions', '文件操作'],
  ['dsh-client-ui-file-drag', '拖拽文件'],
  ['dsh-client-ui-goal', '目标界面'],
  ['dsh-client-ui-input-trigger', '输入触发'],
  ['dsh-client-ui-jobs', '任务界面'],
  ['dsh-client-ui-layout', '布局'],
  ['dsh-client-ui-message-feedback', '消息反馈'],
  ['dsh-client-ui-model-selection', '模型选择'],
  ['dsh-client-ui-open-in-app', '应用内打开'],
  ['dsh-client-ui-permission-presets', '权限预设'],
  ['dsh-client-ui-plan', '计划界面'],
  ['dsh-client-ui-plugin-manager', '插件管理'],
  ['dsh-client-ui-reference', '引用'],
  ['dsh-client-ui-renderer', '渲染器'],
  ['dsh-client-ui-schedule', '定时任务界面'],
  ['dsh-client-ui-secret-mask', '密钥遮罩'],
  ['dsh-client-ui-session', '会话界面'],
  ['dsh-client-ui-shortcuts', '快捷键'],
  ['dsh-client-ui-sidebar-browser', '浏览器侧栏'],
  ['dsh-client-ui-sidebar-documentpreview', '文档预览'],
  ['dsh-client-ui-sidebar-files', '文件侧栏'],
  ['dsh-client-ui-sidebar-right', '右侧栏'],
  ['dsh-client-ui-sidebar-terminal', '终端侧栏'],
  ['dsh-client-ui-skill', '技能界面'],
  ['dsh-client-ui-subagent', '子智能体界面'],
  ['dsh-client-ui-theme', '主题'],
  ['dsh-client-ui-tool', '工具界面'],
  ['dsh-client-ui-trajectory', '执行轨迹'],
  ['dsh-client-ui-user-questions', '用户提问'],
  ['dsh-client-ui-workflow-run', '工作流运行'],
  ['dsh-client-ui-workspace', '工作区界面'],
  ['dsh-client-ui-sidebar', '左侧栏'],
  ['dsh-client-connection', '客户端连接'],
  ['dsh-client-file-upload', '文件上传'],
  ['dsh-client-hmr', '前端热更新'],
  ['dsh-client-locale', '多语言'],
  ['dsh-client-modules', '前端模块'],
  ['dsh-client-product-analytics', '使用统计'],
  ['dsh-client-resources', '前端资源'],
  ['dsh-client-shortcuts', '快捷键'],
  ['dsh-api-account-controller', '账号接口'],
  ['dsh-api-gateway', 'API 网关'],
  ['dsh-api-job-controller', '任务接口'],
  ['dsh-api-remote-access', '远程访问接口'],
  ['dsh-api-remotes', '远程连接'],
  ['dsh-api-session-controller', '会话接口'],
  ['dsh-api-settings-controller', '设置接口'],
  ['dsh-api-terminal-controller', '终端接口'],
  ['dsh-api-workspace-controller', '工作区接口'],
  ['dsh-api-workspace-files', '工作区文件接口'],
  ['dsh-agent-default-model', '默认模型'],
  ['dsh-agent-instructions', '智能体指令'],
  ['dsh-agent-loop', '智能体循环'],
  ['dsh-agent-preset-registry', '预设注册表'],
  ['dsh-agent-preset', '智能体预设'],
  ['dsh-agent', '智能体'],
  ['dsh-attachment-local', '本地附件'],
  ['dsh-authorization', '授权'],
  ['dsh-bash-sandbox', 'Bash 沙箱'],
  ['dsh-compaction-basic', '基础压缩'],
  ['dsh-compaction-image-offload', '图片外置'],
  ['dsh-compaction-tool-result-pruner', '工具结果裁剪'],
  ['dsh-command-compact', '压缩命令'],
  ['dsh-command-feedback', '反馈命令'],
  ['dsh-command-goal', '目标命令'],
  ['dsh-commands', '命令集'],
  ['dsh-config-editor', '配置编辑器'],
  ['dsh-cordis-client-runner', '前端插件运行器'],
  ['dsh-cordis-host-runner', '宿主插件运行器'],
  ['dsh-credentials-local', '本地凭据'],
  ['dsh-deepseek-account-platform', 'DeepSeek 账号平台'],
  ['dsh-deepseek-llm-api-extensions', 'DeepSeek 接口扩展'],
  ['dsh-deliverable-file-references', '交付文件引用'],
  ['dsh-file-reference-local', '本地文件引用'],
  ['dsh-fs-observation-policy', '文件观察策略'],
  ['dsh-fs-sandbox', '文件沙箱'],
  ['dsh-goal-round-driver', '目标轮次驱动'],
  ['dsh-goal', '目标'],
  ['dsh-harness-dev-context', '开发上下文'],
  ['dsh-hmr', '热重载'],
  ['dsh-host-directory-picker-auto', '自动目录选择'],
  ['dsh-host-directory-picker-native', '原生目录选择'],
  ['dsh-host-open-in-app', '应用内打开'],
  ['dsh-host-plugin-inventory', '插件清单'],
  ['dsh-host-product-telemetry-otel', '遥测'],
  ['dsh-host-webserver', '内嵌服务器'],
  ['dsh-jobs-local', '本地任务'],
  ['dsh-llm-deepseek-account', 'DeepSeek 账号模型'],
  ['dsh-llm-deepseek-api-key', 'DeepSeek 密钥模型'],
  ['dsh-llm', '模型接入'],
  ['dsh-otel', '链路追踪'],
  ['dsh-permission-presets', '权限预设'],
  ['dsh-plan-mode', '计划模式'],
  ['dsh-plugin-manager', '插件管理'],
  ['dsh-plugin-package-inventory-deepseek', '插件包清单'],
  ['dsh-ptc-runtime-node', 'PTC 运行时'],
  ['dsh-pwsh-sandbox', 'PowerShell 沙箱'],
  ['dsh-repeat-tool-reminder', '重复工具提醒'],
  ['dsh-sandbox-local', '本地沙箱'],
  ['dsh-sandbox-policy', '沙箱策略'],
  ['dsh-schedule', '定时任务'],
  ['dsh-session-checkpoint-policy', '会话检查点'],
  ['dsh-session-log-deepseek', '会话日志'],
  ['dsh-session-log-export', '会话日志导出'],
  ['dsh-session-persistence-jsonl', '会话持久化'],
  ['dsh-session-projection-cache', '会话投影缓存'],
  ['dsh-session-projection', '会话投影'],
  ['dsh-session-query-sqlite', '会话检索'],
  ['dsh-session-reference', '会话引用'],
  ['dsh-session-stats', '会话统计'],
  ['dsh-session-telemetry-otel', '会话遥测'],
  ['dsh-session-title-first-prompt-llm', '会话标题'],
  ['dsh-session-title', '会话标题'],
  ['dsh-session-turn-outline', '回合大纲'],
  ['dsh-session', '会话'],
  ['dsh-settings', '设置'],
  ['dsh-shell-env', '环境变量'],
  ['dsh-skill-filesystem', '文件系统技能'],
  ['dsh-skill', '技能'],
  ['dsh-spill-local', '本地溢出存储'],
  ['dsh-spill-policy', '溢出策略'],
  ['dsh-storage-domain', '存储域'],
  ['dsh-storage-json', 'JSON 存储'],
  ['dsh-storage', '存储'],
  ['dsh-subagent-fork-in-process', '子智能体内联分叉'],
  ['dsh-subagent-spawn-in-process', '子智能体内联启动'],
  ['dsh-subagent', '子智能体'],
  ['dsh-subprocess-local', '本地子进程'],
  ['dsh-system-prompt', '系统提示词'],
  ['dsh-token-meter', 'Token 计量'],
  ['dsh-tool-bash', 'Bash 工具'],
  ['dsh-tool-call-timeout-policy', '工具超时策略'],
  ['dsh-tool-cordis', '插件工具'],
  ['dsh-tool-executor-native', '原生执行器'],
  ['dsh-tool-executor-ptc', 'PTC 执行器'],
  ['dsh-tool-fs-search', '文件搜索工具'],
  ['dsh-tool-fs', '文件工具'],
  ['dsh-tool-goal', '目标工具'],
  ['dsh-tool-jobs', '任务工具'],
  ['dsh-tool-pwsh', 'PowerShell 工具'],
  ['dsh-tool-skill', '技能工具'],
  ['dsh-tool-subagent-control', '子智能体控制'],
  ['dsh-tool-subagent', '子智能体工具'],
  ['dsh-tool-todo', '待办工具'],
  ['dsh-tool-web', '联网工具'],
  ['dsh-tool-workflow', '工作流工具'],
  ['dsh-tool-working-directory', '工作目录工具'],
  ['dsh-tools', '工具集'],
  ['dsh-typert-loader', '类型加载'],
  ['dsh-typert-registry', '类型注册表'],
  ['dsh-user-approval', '用户审批'],
  ['dsh-user-questions', '用户提问'],
  ['dsh-web-app', '网页应用'],
  ['dsh-web-deepseek-api', 'DeepSeek 网页接口'],
  ['dsh-web-fetch-http', '网页抓取'],
  ['dsh-web-search-deepseek', '联网搜索'],
  ['dsh-web', '网页端'],
  ['dsh-workflow-ptc', '工作流引擎'],
  ['dsh-working-directory', '工作目录'],
  ['dsh-workspace-changes', '工作区改动'],
  ['dsh-workspace', '工作区'],
  ['cordis-plugin-timer', '定时器'],
  ['dsh-mcp-resources', 'MCP 资源'],
  ['dsh-message-feedback', '消息反馈'],
  ['dsh-message-quotes', '消息引用'],
  ['dsh-office-to-pdf', 'Office 转 PDF'],
  ['dsh-client-ui-settings', '设置界面'],
]

/**
 * Match a module name against the alias tables. Exact hits win; otherwise the
 * longest matching prefix is used, so `dsh-client-ui-settings-plugins`
 * resolves through the prefix rules rather than a generic fallback.
 */
function aliasFor(moduleName) {
  const direct = ZH_ALIAS[moduleName]
  if (direct !== undefined) return direct
  const bare = moduleName.replace(/^@deepseek-ai\//, '')
  for (const [prefix, label] of CORE_ALIAS) {
    if (bare === prefix) return label
  }
  for (const [prefix, label] of CORE_ALIAS) {
    if (bare.startsWith(prefix + '-') || bare.startsWith(prefix + '/')) return label
  }
  return null
}

/** Collapse whitespace, keep the first clause, then cap the length. */
function brief(value) {
  const text = value.replace(/\s+/g, ' ').trim()
  if (text.length === 0) return null
  const cut = text.split(/[。；;：:—|]/)[0].trim()
  const head = cut.length >= 10 ? cut : text
  return head.length <= BRIEF_MAX ? head : head.slice(0, BRIEF_MAX - 1) + '…'
}

/** A plugin's own Chinese description, read from its locale directory. */
function zhDescription(moduleName, found) {
  return cached(`zh:${moduleName}`, () => {
    let text = null
    if (found !== null) {
      for (const file of ['zh.json', 'zh-CN.json', 'zh_CN.json']) {
        const candidate = join(found.dir, 'locale', file)
        if (!existsSync(candidate)) continue
        try {
          const parsed = JSON.parse(readFileSync(candidate, 'utf8'))
          const meta = parsed === null || typeof parsed !== 'object' ? null : parsed.meta
          const value = meta === null || typeof meta !== 'object' ? null : firstString(meta.description)
          if (value !== null) {
            text = value
            break
          }
        } catch {
          /* a broken locale file is not worth failing the row for */
        }
      }
    }
    return text
  })
}

/** Row subtitle: hand-written Chinese, else the plugin's Chinese locale, else its own text. */
function describe(moduleName, name, found) {
  const alias = aliasFor(moduleName) ?? aliasFor(name)
  if (alias !== undefined && alias !== null) return alias
  const zh = zhDescription(moduleName, found)
  if (zh !== null) return brief(zh)
  if (found === null) return null
  const raw = firstString(found.manifest.description)
  return raw === null ? null : brief(raw)
}

/** Locate the package.json that owns a module, walking up a few levels. */
function readManifest(moduleName, base) {
  if (!moduleName.startsWith('file://')) {
    if (base === null) return null
    // A bare spec must stay inside node_modules; anything else is not a
    // package this profile could have installed.
    if (
      moduleName.length === 0 ||
      moduleName.includes('..') ||
      moduleName.startsWith('/') ||
      moduleName.startsWith('\\') ||
      moduleName.includes('\\')
    ) {
      return null
    }
    const dir = join(base, 'node_modules', moduleName)
    const candidate = join(dir, 'package.json')
    if (!existsSync(candidate)) return null
    try {
      const parsed = JSON.parse(readFileSync(candidate, 'utf8'))
      if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return { dir, manifest: parsed }
      }
    } catch {
      return null
    }
    return null
  }

  let dir
  try {
    dir = dirname(fileURLToPath(moduleName))
  } catch {
    return null
  }

  for (let depth = 0; depth < 4; depth += 1) {
    const candidate = join(dir, 'package.json')
    if (existsSync(candidate)) {
      try {
        const parsed = JSON.parse(readFileSync(candidate, 'utf8'))
        if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
          return { dir, manifest: parsed }
        }
      } catch {
        return null
      }
    }
    if (basename(dir) === 'node_modules') break
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return null
}

/**
 * Small TTL cache: manifests and locale files must not be cached forever, or an
 * upgraded plugin keeps reporting its old version and description until the
 * host restarts.
 */
const CACHE_TTL = 30_000
const cache = new Map()

function cached(key, read) {
  const now = Date.now()
  const hit = cache.get(key)
  if (hit !== undefined && now - hit.at < CACHE_TTL) return hit.value
  const value = read()
  cache.set(key, { value, at: now })
  return value
}

/** Manifests are read once per module name per TTL; `/state` touches every row. */
function manifestFor(moduleName, base) {
  return cached(`m:${moduleName}`, () => {
    try {
      return readManifest(moduleName, base)
    } catch {
      return null
    }
  })
}

function linksOf(manifest) {
  const repository = manifest.repository
  const raw =
    typeof repository === 'string'
      ? repository
      : repository !== null && typeof repository === 'object'
        ? firstString(repository.url)
        : null
  const homepage = firstString(manifest.homepage)

  let github = null
  for (const candidate of [raw, homepage]) {
    if (candidate === null) continue
    const cleaned = candidate
      .replace(/^git\+/, '')
      .replace(/^git:\/\//, 'https://')
      .replace(/\.git$/, '')
    const match = /github\.com[/:]([^/]+)\/([^/#]+)/.exec(cleaned)
    if (match !== null) {
      github = `https://github.com/${match[1]}/${match[2]}`
      break
    }
  }
  return { github, homepage: github === null ? homepage : null }
}

/** Everything the panel's expanded row shows, beyond what `/state` carries. */
async function detailFor(ctx, entryId) {
  const rows = await readRows(ctx)
  const row = rows.find(item => item.entryId === entryId)
  if (row === undefined) throw new Error(`unknown entry id: ${entryId}`)

  const found = manifestFor(row.moduleName, profileDir(rows))
  const manifest = found === null ? null : found.manifest
  const name = manifest === null ? null : firstString(manifest.name)
  const links = manifest === null ? { github: null, homepage: null } : linksOf(manifest)
  const rawAuthor = manifest === null ? null : manifest.author
  const dependencies =
    manifest === null || manifest.dependencies === null || typeof manifest.dependencies !== 'object'
      ? []
      : Object.keys(manifest.dependencies)

  return {
    row,
    package: {
      name,
      version: manifest === null ? null : firstString(manifest.version),
      description: manifest === null ? null : firstString(manifest.description),
      license: manifest === null ? null : firstString(manifest.license),
      author:
        firstString(rawAuthor) ??
        (rawAuthor !== null && typeof rawAuthor === 'object' ? firstString(rawAuthor.name) : null),
      dir: found === null ? null : found.dir,
      github: links.github,
      homepage: links.homepage,
      npmUrl: name === null ? null : `https://www.npmjs.com/package/${name}`,
      dependencies,
    },
  }
}

/** True for this plugin's own row, whether it is mounted bare or by file spec. */
function isSelfRow(moduleName, patchId) {
  if (typeof patchId === 'string' && SELF_NAMES.some(name => patchId === name || patchId === 'plugin-rack' || patchId === 'plugin-dashboard')) {
    return true
  }
  for (const name of SELF_NAMES) {
    if (moduleName === name) return true
    if (moduleName.includes(`/${name}/`) || moduleName.endsWith(`/${name}`)) return true
  }
  return false
}

function toRow(entry, base) {
  const moduleName = typeof entry.moduleName === 'string' ? entry.moduleName : String(entry.moduleName ?? '')
  const patchId = typeof entry.patchId === 'string' ? entry.patchId : null
  const found = manifestFor(moduleName, base)
  const name = displayName(moduleName)
  return {
    entryId: String(entry.entryId),
    patchId,
    moduleName,
    name: displayName(moduleName),
    version: found === null ? null : firstString(found.manifest.version),
    description: describe(moduleName, name, found),
    enabled: entry.enabled === true,
    phase: entry.fiberPhase === undefined ? null : entry.fiberPhase,
    readOnlyReason: typeof entry.readOnlyReason === 'string' ? entry.readOnlyReason : null,
    diagnostic: typeof entry.diagnostic === 'string' ? entry.diagnostic : null,
    official: moduleName.startsWith('@deepseek-ai/'),
    manageable: patchId !== null,
    self: isSelfRow(moduleName, patchId),
    composed: true,
  }
}

/**
 * First-run default: the plugins this profile installed, not the shipped core.
 * Core rows stay 手动 so a one-click action can never strip the harness down.
 */
function installedRoster(rows) {
  return rows
    .filter(row => row.manageable && !row.official && !row.self)
    .map(row => row.patchId)
}

async function readRows(ctx) {
  const entries = await ctx.pluginManager.listPlugins()
  if (!Array.isArray(entries)) throw new Error('pluginManager.listPlugins() did not return a list')
  const named = entries.map(entry => ({
    moduleName: typeof entry.moduleName === 'string' ? entry.moduleName : '',
  }))
  const base = profileDir(named)
  const rows = entries.map(entry => toRow(entry, base))
  // 关掉（未装配）的包在加载器里没有条目，但用户仍然要能看见它、开关它、
  // 让它跟一键批量和自动清单一起走。把它们合成成行，用 composed:false 标记：
  // 开关这样的行走装配层（setBundleEnabled），而不是 loader 的 entry 开关。
  for (const bundle of await offlineBundles(ctx)) {
    if (rows.some(row => row.moduleName === bundle.name)) continue
    rows.push({
      entryId: 'bundle:' + bundle.name,
      patchId: bundle.name,
      moduleName: bundle.name,
      name: bundle.name,
      version: bundle.version,
      description: bundle.description,
      enabled: false,
      phase: null,
      readOnlyReason: null,
      diagnostic: null,
      official: bundle.official === true,
      manageable: true,
      self: false,
      composed: false,
    })
  }
  return rows
}

/**
 * Bring the 自动 roster up to "everything installed is in it".
 *
 * Pure so it can be tested without a host: the seeding used to run once and
 * then never again, which meant plugins installed later silently never joined
 * the roster. `removed` is the escape hatch — an id the user unticked by hand
 * must not come back on the next refresh.
 */
function catchUpRoster(state, installed) {
  // 两份名单都要补全，但各自有各自的「用户亲手取消过」的记录。
  const grow = (current, blocked, picked) => {
    const list = Array.isArray(current) ? current.slice() : []
    const skip = new Set(Array.isArray(blocked) ? blocked : [])
    const missing = picked.filter(id => id !== null && !list.includes(id) && !skip.has(id))
    return missing.length === 0 ? list : [...list, ...missing]
  }
  const auto = grow(state.auto, state.removed, installed)
  const update = grow(state.update, state.removedUpdate, installed)
  return {
    auto,
    update,
    changed:
      state.seeded !== true ||
      auto.length !== (Array.isArray(state.auto) ? state.auto.length : 0) ||
      update.length !== (Array.isArray(state.update) ? state.update.length : 0),
  }
}

async function snapshot(ctx) {
  const rows = await readRows(ctx)
  const state = roster()

  // 默认全部参与：装上的插件都进名单，用户不必先勾一遍才能用一键更新。
  const gathered = catchUpRoster(state, installedRoster(rows))
  if (gathered.changed) {
    state.auto = gathered.auto
    state.update = gathered.update
    state.seeded = true
    persistRoster()
  }

  // Drop roster entries whose row disappeared, so the count always matches.
  const known = new Set(rows.filter(row => row.manageable).map(row => row.patchId))
  const prune = (list) => (Array.isArray(list) ? list.filter(id => known.has(id)) : [])
  const nextAuto = prune(state.auto)
  const nextUpdate = prune(state.update)
  const nextRemoved = prune(state.removed)
  const nextRemovedUpdate = prune(state.removedUpdate)
  const shrunk =
    nextAuto.length !== (Array.isArray(state.auto) ? state.auto.length : 0) ||
    nextUpdate.length !== (Array.isArray(state.update) ? state.update.length : 0) ||
    nextRemoved.length !== (Array.isArray(state.removed) ? state.removed.length : 0) ||
    nextRemovedUpdate.length !== (Array.isArray(state.removedUpdate) ? state.removedUpdate.length : 0)
  if (shrunk) {
    state.auto = nextAuto
    state.update = nextUpdate
    state.removed = nextRemoved
    state.removedUpdate = nextRemovedUpdate
    persistRoster()
  }

  return {
    ok: true,
    version: VERSION,
    rows,

    roster: state.auto.slice(),
    // 「参与一键更新」是另一份名单，别再让两件事共用一个字段。
    updateRoster: (Array.isArray(state.update) ? state.update : []).slice(),
    supports: { rosterNames: true, splitUpdateRoster: true },
    storage: storageMode,
    statePath: stateFile(),
    bulk: bulkSnapshot(),
  }
}

function describeResult(result) {
  if (result === null || typeof result !== 'object') return 'no result'
  const parts = []
  if (result.error !== undefined && result.error !== null) {
    const message = result.error.message ?? result.error.code
    if (message !== undefined) parts.push(String(message))
  }
  if (Array.isArray(result.warnings) && result.warnings.length > 0) parts.push(result.warnings.join('; '))
  if (result.restartReason !== undefined) parts.push(`restart required (${String(result.restartReason)})`)
  if (parts.length === 0) parts.push(String(result.application ?? 'unknown'))
  return parts.join(' | ')
}

async function setOne(ctx, entryId, enabled, known) {
  const row = known ?? (await readRows(ctx)).find(candidate => candidate.entryId === entryId)
  if (row === undefined) return { entryId, ok: false, message: 'plugin row not found' }
  // Disabling the panel from inside its own request kills the route that is
  // still answering it, so the request would hang until the browser gives up.
  if (row.self) {
    return { entryId, ok: false, message: 'the dashboard refuses to switch itself off from here' }
  }
  if (!row.manageable) {
    return { entryId, ok: false, message: `row is read-only (${row.readOnlyReason ?? 'unaddressable'})` }
  }

  let result
  try {
    if (row.composed === false) {
      // 未装配的行没有 loader 条目可开关：装配清单才是它的开关。
      if (typeof ctx.pluginManager.setBundleEnabled !== 'function') {
        return { entryId, ok: false, message: 'this host cannot switch a bundle layer' }
      }
      result = await ctx.pluginManager.setBundleEnabled(row.name, enabled)
    } else {
      result = await ctx.pluginManager.setPluginEnabled(row.entryId, enabled)
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return { entryId, ok: false, message }
  }

  const application = result === null || typeof result !== 'object' ? undefined : result.application
  if (application === 'failed' || application === 'cancelled') {
    return { entryId, ok: false, application, message: describeResult(result) }
  }
  return {
    entryId,
    ok: true,
    application,
    // `overridden` and `restart-required` are saved-but-not-live outcomes.
    notice:
      application === 'applied' ? undefined : describeResult(result),
  }
}

/**
 * Bundles the profile still has installed but is not composing.
 *
 * `listPlugins()` can only report what the loader composed, so a bundle that was
 * switched off has no row anywhere in the panel — it reads as "the plugin is
 * gone", and the only way back is the plugin market. `listBundles()` knows the
 * full inventory: an installed bundle with `enabled: false` is exactly the row
 * this returns, and `setBundleEnabled()` switches it back on without touching
 * the dependency at all.
 *
 * The profile roots are filtered out: switching either of them off cannot be
 * recovered from inside the panel.
 */
async function offlineBundles(ctx) {
  const manager = ctx.pluginManager
  if (manager === null || manager === undefined || typeof manager.listBundles !== 'function') return []
  let listed = []
  try {
    listed = await manager.listBundles()
  } catch {
    return []
  }
  const roots = new Set([
    ...SELF_NAMES,
    'dsh-base',
    'dsh-web-app',
    '@deepseek-ai/dsh-base',
    '@deepseek-ai/dsh-web-app',
  ])
  return (Array.isArray(listed) ? listed : [])
    .filter(bundle => bundle !== null && typeof bundle === 'object')
    .filter(bundle => bundle.installed === true && bundle.enabled !== true)
    .filter(bundle => bundle.availability !== 'missing')
    .filter(bundle => !roots.has(bundle.name))
    .map(bundle => ({
      name: String(bundle.name),
      version: typeof bundle.version === 'string' ? bundle.version : null,
      official: bundle.official === true,
      removable: bundle.removable === true,
      description: typeof bundle.description === 'string' ? bundle.description : null,
      title:
        bundle.meta !== null && typeof bundle.meta === 'object' && typeof bundle.meta.title === 'string'
          ? bundle.meta.title
          : null,
      rows: Array.isArray(bundle.rows) ? bundle.rows.length : 0,
      readOnlyReason: typeof bundle.readOnlyReason === 'string' ? bundle.readOnlyReason : null,
    }))
}
async function actPlugin(ctx, body) {
  const entryId = typeof body.entryId === 'string' ? body.entryId : ''
  if (entryId.length === 0) throw new Error('entryId is required')

  const rows = await readRows(ctx)
  const row = rows.find(candidate => candidate.entryId === entryId)
  if (row === undefined) return { ok: false, result: { entryId, ok: false, message: 'plugin row not found' } }

  let result
  if (typeof body.enabled === 'boolean') {
    result = await setOne(ctx, entryId, body.enabled, row)
  }

  // 「参与一键更新」是独立的一份名单：更新页的勾选只动它，不再牵动自动/手动。
  if (typeof body.update === 'boolean') {
    const state = roster()
    const list = Array.isArray(state.update) ? state.update : []
    const blocked = Array.isArray(state.removedUpdate) ? state.removedUpdate : []
    if (row.patchId === null) {
      result = { entryId, ok: false, message: 'row cannot join the update roster (read-only)' }
    } else if (body.update) {
      if (!list.includes(row.patchId)) state.update = [...list, row.patchId]
      state.removedUpdate = blocked.filter(id => id !== row.patchId)
      persistRoster()
      result = result ?? { entryId, ok: true, application: 'applied' }
    } else {
      state.update = list.filter(id => id !== row.patchId)
      state.removedUpdate = blocked.includes(row.patchId) ? blocked : [...blocked, row.patchId]
      persistRoster()
      result = result ?? { entryId, ok: true, application: 'applied' }
    }
  }

  if (typeof body.auto === 'boolean') {
    const state = roster()
    if (row.patchId === null) {
      result = { entryId, ok: false, message: 'row cannot join the 自动 roster (read-only)' }
    } else if (body.auto) {
      if (!state.auto.includes(row.patchId)) state.auto.push(row.patchId)
      state.removed = (Array.isArray(state.removed) ? state.removed : []).filter(id => id !== row.patchId)
      persistRoster()
      result = result ?? { entryId, ok: true, application: 'applied' }
    } else {
      state.auto = state.auto.filter(id => id !== row.patchId)
      const removed = Array.isArray(state.removed) ? state.removed : []
      if (!removed.includes(row.patchId)) removed.push(row.patchId)
      state.removed = removed
      persistRoster()
      result = result ?? { entryId, ok: true, application: 'applied' }
    }
  }

  const settled = result ?? { entryId, ok: true }
  // `applied` means the change is live, so the touched row can be patched in
  // place. Anything else (read-only, failed, restart-required) needs the full
  // state so the panel never shows a switch that does not match reality.
  const applied =
    settled.ok === true && (settled.application === undefined || settled.application === 'applied')
  if (!applied) {
    return { ...(await snapshot(ctx)), result: settled }
  }

  const patched = { ...row }
  if (typeof body.enabled === 'boolean') {
    patched.enabled = body.enabled
    patched.phase = body.enabled ? 'active' : null
    // 未装配的行打开之后就是装配好的行了：不同步这个标记，界面会一边把开关
    // 拨到「开」，一边继续挂「已关闭」的标签，直到下一次整份状态刷新。
    if (row.composed === false) patched.composed = body.enabled
  }
  return { ok: true, patch: true, row: patched, roster: roster().auto.slice(), result: settled }
}

/** The profile's patch document plus the live entries it addresses. */
async function patchContext(ctx) {
  const profile = ctx.get ? ctx.get('profileContext') : undefined
  if (profile === undefined || typeof profile.patchPath !== 'string') {
    throw new Error('profileContext is unavailable; cannot write the profile patch')
  }
  const resolved = require.resolve('yaml', { paths: [join(profile.dir, 'node_modules')] })
  const yaml = await import(pathToFileURL(resolved).href)
  return { profile, yaml }
}

/**
 * Write `disabled` for several rows in one pass and never reload anything.
 *
 * `pluginManager.setPluginEnabled` reconciles the whole profile on every call,
 * which is what makes a bulk toggle take seconds per row. For the "turn things
 * off, update them, restart" workflow the reload is wasted work: the caller
 * restarts anyway, so persisting the intent is enough.
 *
 * The current state is read from the patch document, never from the runtime
 * rows: a save-mode run does not change what is running, so comparing against
 * `row.enabled` would treat an already-saved toggle as "nothing to do" and drop
 * the entry it should restore.
 */
/**
 * 装配清单层面的开关：只写 package.json 的 dsh.profile.bundles，不重载。
 *
 * `save` 模式的批量操作要能把未装配的包一起写进去，而它们没有 loader 条目、
 * 也就没有可以写 disabled 覆盖的 patch id；装配清单才是它们的持久状态。
 */
async function composeBundles(ctx, names, enabled) {
  if (!Array.isArray(names) || names.length === 0) return { changed: 0, unchanged: 0 }
  const facts = profileFacts(ctx)
  if (facts === null) return { changed: 0, unchanged: names.length }
  const file = join(facts.dir, 'package.json')
  const parsed = JSON.parse(readFileSync(file, 'utf8'))
  parsed.dsh = parsed.dsh === undefined || parsed.dsh === null ? {} : parsed.dsh
  parsed.dsh.profile = parsed.dsh.profile === undefined || parsed.dsh.profile === null ? {} : parsed.dsh.profile
  const current = Array.isArray(parsed.dsh.profile.bundles) ? parsed.dsh.profile.bundles : []
  let next = current.slice()
  let changed = 0
  let unchanged = 0
  for (const name of names) {
    const has = next.includes(name)
    if (has === enabled) {
      unchanged += 1
      continue
    }
    next = enabled === true ? next.concat([name]) : next.filter(one => one !== name)
    changed += 1
  }
  if (changed > 0) {
    parsed.dsh.profile.bundles = next
    writeFileSync(file, JSON.stringify(parsed, null, 2) + '\n', 'utf8')
  }
  return { changed, unchanged }
}

async function writeEnabledBatch(ctx, rows, enabled) {
  const { profile, yaml } = await patchContext(ctx)
  const { parseDocument } = yaml
  const filename = profile.patchPath

  let text
  try {
    text = readFileSync(filename, 'utf8')
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
    text = '[]\n'
  }

  const document = parseDocument(text, {
    customTags: [{ tag: 'tag:yaml.org,2002:js', resolve: value => value }],
  })
  const broken = document.errors[0]
  if (broken !== undefined) throw new Error(`the profile patch is not valid YAML: ${broken.message}`)
  if (!Array.isArray(document.contents?.items)) {
    throw new Error('the profile patch is not a YAML sequence')
  }

  const items = document.contents.items
  const want = enabled !== true
  const changed = []
  let unchanged = 0
  // Overrides this panel created. Only those are removed again on enable, so a
  // pre-existing `disabled: false` in the user's profile is never touched.
  const created = new Set(roster().created)

  /** The index of the last id-matching override, the way the shipped writer finds it. */
  const locate = (id, name) => {
    for (let cursor = items.length - 1; cursor >= 0; cursor -= 1) {
      const item = items[cursor]
      if (item === null || typeof item.get !== 'function') continue
      if (item.get('insert') !== undefined) continue
      if (item.get('id') !== id) continue
      const declared = item.get('name')
      if (declared !== undefined && declared !== null && declared !== name) continue
      return cursor
    }
    return -1
  }

  for (const row of rows) {
    const index = locate(row.patchId, row.moduleName)
    if (index === -1) {
      // No override yet, so the composition's value is whatever is running.
      // Only append when that differs from what was asked for.
      if (row.enabled === enabled) {
        unchanged += 1
      } else {
        document.add({ id: row.patchId, disabled: want })
        created.add(row.patchId)
        changed.push(row.patchId)
      }
      continue
    }
    // An override decides on its own; `undefined` means it inherits, so it must
    // be written even when the inherited value happens to match.
    const current = document.getIn([index, 'disabled'])
    if (current !== undefined && current === want) {
      unchanged += 1
      continue
    }
    if (enabled === true && current === true) {
      if (created.has(row.patchId)) {
        // The override exists only because this panel disabled the plugin, so
        // re-enabling makes it redundant. Drop the entry again so the user's
        // profile does not collect `disabled: false` litter.
        document.delete(index)
        created.delete(row.patchId)
      } else {
        // A pre-existing override belongs to the user: keep the entry and
        // write the value back explicitly, so the file ends up exactly as it
        // started instead of losing the key.
        document.setIn([index, 'disabled'], false)
      }
      changed.push(row.patchId)
      continue
    }
    document.setIn([index, 'disabled'], want)
    changed.push(row.patchId)
  }

  if (changed.length === 0) return { changed, unchanged, patchPath: filename }

  const temp = `${filename}.tmp-${process.pid}`
  writeFileSync(temp, String(document), { mode: 0o600 })
  renameSync(temp, filename)
  // Remember which overrides this panel owns, so a later enable can remove
  // exactly those and nothing else.
  const state = roster()
  state.created = [...created]
  persistRoster()
  return { changed, unchanged, patchPath: filename }
}
function inScope(row, scope) {
  if (!row.manageable) return false
  if (scope === 'failed') return row.phase === 'failed'
  // The panel's pages leave failed rows out of 已安装插件 and 核心组件, so the
  // server side must exclude them too or a bulk action hits more rows than the
  // button's own count promises.
  if (scope === 'installed') return !row.official && row.phase !== 'failed'
  if (scope === 'core') return row.official && row.phase !== 'failed'
  return false
}

/**
 * A running bulk job. `setPluginEnabled` costs a file lock, an HMR exclusive
 * lock, two full listPlugins() calls and one reconcile each, so N rows always
 * costs N of those no matter how the calls are ordered. The panel therefore
 * accepts a job, answers at once, and reports progress while it runs.
 */
let bulkJob = null

/**
 * One profile-mutating operation at a time.
 *
 * The host gives plugins no lock of their own, and two installs / uninstalls /
 * updates racing on the same package.json + pnpm-lock.yaml can interleave their
 * writes and leave a profile nobody can install into. A bulk run already
 * serializes itself through `bulkJob`; this flag extends the same rule to
 * install / uninstall / update / extras, and to a bulk run starting while one
 * of them is still in flight.
 */
let mutationBusy = false

const BUSY_MESSAGE = '已经有一个安装 / 卸载 / 更新 / 批量操作在进行中，等它结束再试'

function beginMutation() {
  if (mutationBusy) return false
  if (bulkJob !== null && bulkJob.running) return false
  mutationBusy = true
  return true
}

function endMutation() {
  mutationBusy = false
}

function bulkSnapshot() {
  if (bulkJob === null) return null
  return {
    running: bulkJob.running,
    enabled: bulkJob.enabled,
    scope: bulkJob.scope,
    finished: bulkJob.finished,
    total: bulkJob.total,
    failed: bulkJob.failed,
    unchanged: bulkJob.unchanged,
    guarded: bulkJob.guarded,
    current: bulkJob.current,
    cancelled: bulkJob.cancelled === true,
  }
}

/** Ask the running bulk job to stop after the row it is on. */
function cancelBulk() {
  if (bulkJob === null || !bulkJob.running) return { ok: false, message: 'no bulk run is in progress' }
  bulkJob.cancelled = true
  return { ok: true, cancelled: true, bulk: bulkSnapshot() }
}

async function actBulk(ctx, enabled, scope, mode) {
  if (bulkJob !== null && bulkJob.running) {
    return { ok: false, message: 'a bulk run is already in progress' }
  }
  if (mutationBusy) {
    return { ok: false, message: '一个安装或卸载还在进行中，等它结束再操作' }
  }
  // Claim the mutex before the first await. Checking here and locking later
  // let two bulk requests both pass the check, and the second one's finally
  // then released the first one's lock.
  if (!beginMutation()) return { ok: false, message: BUSY_MESSAGE }

  let rows
  try {
    rows = await readRows(ctx)
  } catch (error) {
    endMutation()
    throw error
  }
  const state = roster()
  const auto = new Set(state.auto)
  const scoped = typeof scope === 'string' && scope.length > 0

  // A row only follows 一键 when it is on the 自动 roster. The scope narrows
  // that set to the visible page; it never widens it. Marking a row 手动 has to
  // mean the bulk buttons leave it alone.
  const wanted = rows.filter(
    row =>
      row.manageable &&
      row.patchId !== null &&
      auto.has(row.patchId) &&
      (!scoped || inScope(row, scope)),
  )

  // Hard guard, independent of the roster. The panel's own row is the one case
  // that must never be touched: disabling it inside this very request kills the
  // route that is still answering it.
  const guards = []
  const targets = []
  let unchanged = 0
  for (const row of wanted) {
    if (row.self) {
      guards.push({ entryId: row.entryId, name: row.name, reason: 'self' })
    } else if (mode !== 'save' && row.enabled === enabled) {
      // Already in the target state: a full unload/load cycle for nothing.
      // `save` must NOT take this shortcut: it compares against the FILE, and
      // a row that was save-disabled earlier still runs enabled, so the
      // runtime state would mask a pending `disabled: true` override forever.
      unchanged += 1
    } else {
      targets.push(row)
    }
  }

  // `save` writes the patch and reloads nothing. It is the right mode for the
  // "stop everything, update it, restart" workflow, which restarts anyway.
  if (mode === 'save') {
    try {
      const composedRows = targets.filter(row => row.composed !== false)
      const offlineNames = targets.filter(row => row.composed === false).map(row => row.name)
      const written = await writeEnabledBatch(ctx, composedRows, enabled)
      const composed = await composeBundles(ctx, offlineNames, enabled)
      return {
        ok: true,
        saved: true,
        total: written.changed.length + composed.changed,
        unchanged: unchanged + written.unchanged + composed.unchanged,
        guarded: guards.length,
        patchPath: written.patchPath,
        bulk: null,
      }
    } finally {
      endMutation()
    }
  }

  bulkJob = {
    running: true,
    enabled,
    scope: scoped ? scope : 'auto',
    finished: 0,
    total: targets.length,
    failed: 0,
    unchanged,
    guarded: guards.length,
    current: null,
    cancelled: false,
  }

  // Detached on purpose: the HTTP response returns immediately and the client
  // polls /state, which carries `bulk`. It keeps a local reference because a
  // later run replaces `bulkJob` while this one may still be finishing.
  const job = bulkJob
  // The mutex was claimed before the first await; the detached run owns it
  // until its finally hands it back.
  void (async () => {
    for (const row of targets) {
      if (job.cancelled) break
      job.current = row.name
      // Pass the row we already read: setOne would otherwise call readRows()
      // again, and that is a full pluginManager.listPlugins() over ~200 loader
      // entries on every single row of the batch. The row cannot have changed
      // under us either — the mutation mutex is held for the whole run.
      const outcome = await setOne(ctx, row.entryId, enabled, row)
      if (outcome.ok !== true) job.failed += 1
      job.finished += 1
    }
  })()
    .catch(() => {
      job.failed += 1
    })
    .finally(() => {
      job.current = null
      job.running = false
      endMutation()
    })

  return {
    ok: true,
    accepted: true,
    total: targets.length,
    unchanged,
    guarded: guards.length,
    bulk: bulkSnapshot(),
  }
}

async function actRoster(ctx, mode, scope, auto) {
  const rows = await readRows(ctx)
  const state = roster()

  // 'group' 按范围（installed/core/failed），'names' 按包名列表——更新页的
  // 「全选 / 全不选」用它，一次请求改完整份名单，不用发 N 个单行请求。
  if (mode !== 'group' && mode !== 'names') throw new Error(`unknown roster mode: ${mode}`)
  const pick = mode === 'group'
    ? rows.filter(row => inScope(row, scope))
    : rows.filter(row => Array.isArray(scope) && scope.includes(row.name))
  const wanted = new Set(pick.map(row => row.patchId).filter(id => id !== null))
  if (mode === 'names') {
    // 按名单批量勾选只服务更新页 —— 它改的是「参与一键更新」，不是自动/手动。
    const list = Array.isArray(state.update) ? state.update.slice() : []
    const blocked = new Set(Array.isArray(state.removedUpdate) ? state.removedUpdate : [])
    if (auto === true) {
      for (const id of wanted) {
        if (!list.includes(id)) list.push(id)
        blocked.delete(id)
      }
    } else {
      for (const id of wanted) {
        const at = list.indexOf(id)
        if (at >= 0) list.splice(at, 1)
        blocked.add(id)
      }
    }
    state.update = list
    state.removedUpdate = [...blocked]
  } else {
    const removed = new Set(Array.isArray(state.removed) ? state.removed : [])
    if (auto === true) {
      for (const id of wanted) {
        if (!state.auto.includes(id)) state.auto.push(id)
        removed.delete(id)
      }
    } else {
      state.auto = state.auto.filter(id => !wanted.has(id))
      for (const id of wanted) removed.add(id)
    }
    state.removed = [...removed]
  }
  state.seeded = true
  persistRoster()
  return await snapshot(ctx)
}

function send(res, status, payload) {
  // 面板可能在一次 25 分钟的装包中途被关掉。结果写不回那个已经断掉的连接不算
  // 失败——任务本身记在 job.json 里，下次打开面板由 /job 接回去。
  if (res.writableEnded || res.destroyed) return
  res.once('error', () => {})
  const body = JSON.stringify(payload)
  try {
    res.statusCode = status
    res.setHeader('content-type', 'application/json; charset=utf-8')
    res.setHeader('cache-control', 'no-store')
    res.end(body)
  } catch (error) {
    // 连接已经没了：同上，任务照样跑完了。
    void error
  }
}

const MAX_BODY = 1 << 20

/** An input problem the caller caused; answers its status instead of a 500. */
class HttpError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

async function readJsonBody(req) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > MAX_BODY) throw new HttpError(413, 'request body is too large')
    chunks.push(chunk)
  }
  const text = Buffer.concat(chunks).toString('utf8').trim()
  if (text.length === 0) return {}
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new HttpError(400, 'request body is not valid JSON')
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new HttpError(400, 'request body must be a JSON object')
  }
  return parsed
}

/* ------------------------------ update checking ------------------------------ */

/** Packages the runtime itself provides; those are never fetched from npm. */
const HOST_SCOPE = /^@deepseek-ai\//
const REGISTRY_TIMEOUT = 12000
const UPDATE_CONCURRENCY = 6

/** The profile's package.json and dependencies, or null when unreadable. */
function profileFacts(ctx) {
  try {
    const profile = ctx.get === undefined ? undefined : ctx.get('profileContext')
    if (profile === undefined || profile === null || typeof profile.dir !== 'string') return null
    const file = join(profile.dir, 'package.json')
    const parsed = JSON.parse(readFileSync(file, 'utf8'))
    if (parsed === null || typeof parsed !== 'object') return null
    const deps = parsed.dependencies
    if (deps === null || typeof deps !== 'object') return null
    return { dir: profile.dir, file, deps, parsed }
  } catch {
    return null
  }
}

/**
 * The registry answer for a package's `latest` dist-tag. The profile's own
 * registry is asked first — a user behind a mirror should not be forced through
 * npmjs.org — and npmjs.org is the fallback, because a mirror that lags or
 * lacks a package must not read as "no update".
 */
async function npmLatest(name, base, signal) {
  const encoded = name.startsWith('@') ? name.replace('/', '%2f') : name
  const configured = typeof base === 'string' && base.trim().length > 0 ? base.trim() : null
  const roots = []
  if (configured !== null) roots.push(configured.replace(/\/+$/, '') + '/')
  if (roots[0] !== 'https://registry.npmjs.org/') roots.push('https://registry.npmjs.org/')
  const errors = []
  for (const root of roots) {
    if (signal !== undefined && signal !== null && signal.aborted) throw new Error('cancelled by the user')
    try {
      // The query is user-cancellable: cancelling used to do nothing while a
      // slow mirror was being asked, so the panel said "cancelled" and kept
      // waiting.
      const timeout = AbortSignal.timeout(REGISTRY_TIMEOUT)
      const response = await fetchAny(`${root}${encoded}/latest`, {
        signal: signal === undefined || signal === null ? timeout : AbortSignal.any([timeout, signal]),
        headers: { accept: 'application/json' },
      })
      if (!response.ok) throw new Error(`registry answered ${response.status}`)
      const body = await response.json()
      if (body === null || typeof body !== 'object' || typeof body.version !== 'string') {
        throw new Error('registry returned no version')
      }
      return body.version
    } catch (error) {
      errors.push(`${root} ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  throw new Error(errors.join('; '))
}

/**
 * Dependencies this panel is willing to touch: host-provided ones are skipped,
 * and every spec it understands becomes a target.
 *
 * This used to accept exact pins only, which quietly meant that a profile using
 * `^1.2.3` — the normal way to write a dependency — had those packages invisible
 * to "update everything". The range still matters though: it is kept on the
 * target so the checker can refuse a registry version the user's own range
 * excludes, instead of silently jumping a major.
 */
function eligibleDeps(facts) {
  const out = []
  for (const [name, spec] of Object.entries(facts.deps)) {
    if (HOST_SCOPE.test(name)) continue
    if (typeof spec !== 'string') continue
    const parsed = parseSpec(spec)
    if (parsed.kind === 'unsupported') continue
    // What is actually installed beats the range floor: with `^1.2.3` installed
    // at 1.9.0, comparing against the floor would report an update to 1.9.0.
    const installed = installedVersion(facts.dir, name)
    const current = installed !== null ? installed : parsed.floor
    if (current === null) continue
    out.push({ name, current, spec: spec.trim(), kind: parsed.kind, floor: parsed.floor })
  }
  return out
}

async function checkUpdates(ctx) {
  const facts = profileFacts(ctx)
  if (facts === null) return { ok: false, message: 'profile package.json is unavailable' }
  const base = await configuredRegistry(ctx)
  const targets = eligibleDeps(facts)
  const rows = new Array(targets.length)
  let cursor = 0
  async function worker() {
    for (;;) {
      const index = cursor
      cursor += 1
      if (index >= targets.length) return
      const target = targets[index]
      try {
        const latest = await npmLatest(target.name, base, activeJobAbort === null ? undefined : activeJobAbort.signal)
        const ahead = compareVersions(latest, target.current) > 0
        // An exact pin has no range to violate. Anything else does, and a
        // major bump the user's own `^`/`~` excludes is not this panel's call.
        const inRange = target.kind === 'exact' || satisfiesSpec(latest, target.spec)
        // Same version on both sides is never an update. A check that runs
        // while pnpm is still writing node_modules reads the pre-install
        // version as "current", which used to produce rows like
        // v0.4.20 ➡ v0.4.20 that the panel then drew as an update button.
        rows[index] = {
          name: target.name,
          current: target.current,
          latest,
          spec: target.spec,
          kind: target.kind,
          // `ahead` already means strictly greater, so equal versions fall through
          // to false on both. Keeping the name explicit: a same-version row is
          // neither an update nor an out-of-range newer release.
          hasUpdate: ahead && inRange,
          outOfRange: ahead && !inRange,
          error: null,
        }
      } catch (error) {
        rows[index] = {
          name: target.name,
          current: target.current,
          latest: null,
          spec: target.spec,
          kind: target.kind,
          hasUpdate: false,
          outOfRange: false,
          error: error instanceof Error ? error.message : String(error),
        }
      }
    }
  }
  const workers = []
  for (let index = 0; index < Math.min(UPDATE_CONCURRENCY, targets.length); index += 1) workers.push(worker())
  await Promise.all(workers)
  const list = rows.filter(row => row !== undefined).sort((a, b) => a.name.localeCompare(b.name))
  return {
    ok: true,
    dir: facts.dir,
    registry: base,
    checked: list.length,
    updates: list.filter(row => row.hasUpdate).length,
    rows: list,
  }
}

/**
 * Hold every live Agent at the host's public maintenance boundary.
 *
 * Replacing files under a running Agent mixes old in-memory modules with new
 * ones on disk, which is exactly how a marketplace update corrupts a profile.
 * `runMaintenance` claims a truly idle Agent synchronously and latches later
 * inbox work until the returned promise settles. A synchronous throw means an
 * Agent is mid-turn right now; the caller reports that instead of racing it.
 */
/**
 * Hold every running agent against starting new work, so a pnpm run can rewrite
 * node_modules without a session loading code from it half-way.
 *
 * The returned function release()s every hold and carries a `gated` flag.
 *
 * When the host exposes no `agents` service there is nothing to hold, and the
 * caller proceeds **without** the idle guarantee. That used to be indistinguishable
 * from "we waited and every agent was idle": both produced a silently successful
 * run, so a host where the service is missing (an older release, a headless
 * profile, a renamed service) would rewrite node_modules under a live session
 * and report success. The flag lets the caller tell the user which one happened.
 */
async function holdAgents(ctx) {
  const service = ctx.get === undefined ? undefined : ctx.get('agents')
  const available = service !== undefined && service !== null && typeof service.list === 'function'
  const listed = available ? service.list() : []
  const handles = []
  for (const agent of Array.isArray(listed) ? listed : []) {
    if (agent === null || typeof agent !== 'object') continue
    if (typeof agent.id !== 'string' || agent.id === '') continue
    if (typeof agent.whenIdle !== 'function' || typeof agent.runMaintenance !== 'function') continue
    handles.push(agent)
  }
  // No service at all: there is no gate to take, but the caller must know that
  // it is proceeding unguarded rather than after a successful wait.
  if (!available) {
    const releaseUngated = () => {}
    releaseUngated.gated = false
    releaseUngated.agents = 0
    return releaseUngated
  }
  const held = []
  const releaseAll = () => {
    while (held.length > 0) {
      const entry = held.pop()
      entry.controller.abort()
      entry.release()
    }
  }
  releaseAll.gated = true
  releaseAll.agents = handles.length
  try {
    for (const handle of handles) {
      let release = () => {}
      const gate = new Promise(resolve => {
        release = resolve
      })
      const controller = new AbortController()
      let running
      try {
        running = handle.runMaintenance(signal => {
          if (signal.aborted) {
            release()
            return gate
          }
          signal.addEventListener('abort', () => release(), { once: true })
          return gate
        })
      } catch (error) {
        release()
        throw error
      }
      if (running !== undefined && running !== null && typeof running.catch === 'function') {
        void running.catch(() => release())
      }
      held.push({ controller, release })
    }
  } catch (error) {
    releaseAll()
    throw error
  }
  return releaseAll
}

/** The pnpm entry point installed next to the host, or null. */
function pathEntries() {
  const raw = typeof process.env.PATH === 'string' ? process.env.PATH : ''
  const separator = process.platform === 'win32' ? ';' : ':'
  return raw
    .split(separator)
    .map(entry => entry.trim().replace(/^"|"$/g, ''))
    .filter(entry => entry !== '')
}

/** Find `name`, with the platform's usual suffixes, on PATH. */
function resolveOnPath(name) {
  const suffixes = process.platform === 'win32' ? ['', '.cmd', '.exe'] : ['']
  for (const dir of pathEntries()) {
    for (const suffix of suffixes) {
      const candidate = join(dir, name + suffix)
      if (existsSync(candidate)) return candidate
    }
  }
  return null
}

/**
 * The pnpm entry script, or null when pnpm is not installed.
 *
 * A global install is a launcher: on Windows it sits under %APPDATA%\npm, on
 * macOS and Linux it is a symlink in a bin directory pointing at
 * `<prefix>/lib/node_modules/pnpm/bin/pnpm.cjs`. Resolving that symlink gives
 * a script `node` can run directly; the plugin never depends on a shell shim,
 * because a shim is what breaks first under a bare environment.
 */
function pnpmScript() {
  const candidates = []
  if (process.platform === 'win32') {
    const appData = typeof process.env.APPDATA === 'string' ? process.env.APPDATA.trim() : ''
    if (appData !== '') candidates.push(join(appData, 'npm', 'node_modules', 'pnpm', 'bin', 'pnpm.mjs'))
    const localData = typeof process.env.LOCALAPPDATA === 'string' ? process.env.LOCALAPPDATA.trim() : ''
    if (localData !== '') candidates.push(join(localData, 'pnpm', 'node_modules', 'pnpm', 'bin', 'pnpm.mjs'))
  } else {
    const home = homedir()
    const pnpmHome = typeof process.env.PNPM_HOME === 'string' ? process.env.PNPM_HOME.trim() : ''
    if (pnpmHome !== '') candidates.push(join(pnpmHome, 'node_modules', 'pnpm', 'bin', 'pnpm.mjs'))
    candidates.push(
      join(home, '.local', 'share', 'pnpm', 'node_modules', 'pnpm', 'bin', 'pnpm.mjs'),
      join(home, 'Library', 'pnpm', 'node_modules', 'pnpm', 'bin', 'pnpm.mjs'),
      '/usr/local/lib/node_modules/pnpm/bin/pnpm.mjs',
      '/opt/homebrew/lib/node_modules/pnpm/bin/pnpm.mjs',
      '/usr/lib/node_modules/pnpm/bin/pnpm.mjs',
    )
  }
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate
  }
  const shim = resolveOnPath('pnpm')
  if (shim !== null) {
    try {
      const real = realpathSync(shim)
      // A real script: node can run it directly.
      if (/\.(c|m)?js$/i.test(real) && existsSync(real)) return real
      // The standalone installer and a corepack shim both land on PATH as a
      // wrapper (pnpm.exe, pnpm.cmd) that node cannot execute. They still work
      // through their own launcher, so keep them instead of reporting "no pnpm".
      if (process.platform === 'win32' && /\.(exe|cmd|bat|ps1)$/i.test(real) && existsSync(real)) return real
    } catch {
      // Not a symlink (or not ours to resolve): fall through.
    }
  }
  return null
}

/**
 * Pick the interpreter that runs pnpm.
 *
 * On Windows the host's own `process.execPath` is an Electron GUI binary. A GUI
 * process owns no console at all, so `windowsHide` has nothing to suppress: the
 * direct child gets no console, and every console descendant pnpm starts (git,
 * tar, build scripts) finds no console to inherit, so Windows allocates a fresh
 * one and a terminal window pops up on the user's desktop.
 *
 * Spawning a real console node instead gives the direct child a *hidden*
 * console, which all of its descendants inherit. Nothing is ever shown, and a
 * real node is also the interpreter pnpm actually expects.
 */
let nodeRuntimeCache = null

/**
 * How to start pnpm, given whatever pnpmScript() resolved to.
 *
 * Exported for test/pnpm-command.mjs: the quoting rules here are the part that
 * cannot be checked by reading the code, and a wrong quote is a silent failure
 * that reads as "pnpm is broken".
 */
export function pnpmInvocation(script, args, execPath) {
  const batch = /\.(cmd|bat)$/i.test(script)
  const powershell = /\.ps1$/i.test(script)
  const exe = /\.exe$/i.test(script)
  if (batch) {
    // cmd strips one outer pair of quotes under /s, so the whole command gets
    // wrapped once and every part is quoted again inside.
    const inner = [script, ...args].map(one => '"' + one + '"').join(' ')
    return { command: process.env.ComSpec || 'cmd.exe', commandArgs: ['/d', '/s', '/c', '"' + inner + '"'], electron: false }
  }
  if (powershell) {
    return {
      command: 'powershell.exe',
      commandArgs: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, ...args],
      electron: false,
    }
  }
  if (exe) return { command: script, commandArgs: args, electron: false }
  return { command: execPath, commandArgs: [script, ...args], electron: execPath === process.execPath }
}


function nodeRuntime() {
  if (nodeRuntimeCache !== null) return nodeRuntimeCache
  const execPath = typeof process.execPath === 'string' ? process.execPath : ''
  nodeRuntimeCache = execPath
  const found = resolveOnPath('node')
  if (found !== null) {
    try {
      const real = realpathSync(found)
      if (real !== '' && existsSync(real)) {
        nodeRuntimeCache = real
        if (execPath === '' || real.toLowerCase() !== execPath.toLowerCase()) return nodeRuntimeCache
      }
    } catch {
      // Keep the Electron fallback below.
    }
  }
  if (process.platform !== 'win32') {
    for (const candidate of ['/usr/local/bin/node', '/opt/homebrew/bin/node', '/usr/bin/node']) {
      if (existsSync(candidate)) {
        nodeRuntimeCache = candidate
        break
      }
    }
    return nodeRuntimeCache
  }
  const seen = new Set()
  for (const dir of pathEntries()) {
    const key = dir.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    const candidate = join(dir, 'node.exe')
    if (!existsSync(candidate)) continue
    if (execPath !== '' && candidate.toLowerCase() === execPath.toLowerCase()) continue
    nodeRuntimeCache = candidate
    break
  }
  return nodeRuntimeCache
}

/** Run pnpm headlessly: no shell, no console, and no window the user can see. */
const PNPM_TIMEOUT = 10 * 60 * 1000

/**
 * Kill a spawned process and everything it spawned.
 *
 * `child.kill()` on Windows only terminates the direct child. pnpm forks
 * downloaders and build scripts, and those orphans keep writing into
 * node_modules after pnpm itself is gone — which is the one way a timed-out
 * update can still corrupt the profile. So kill the whole tree.
 */
function killTree(child) {
  try {
    if (process.platform === 'win32' && typeof child.pid === 'number') {
      const killer = spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], {
        windowsHide: true,
        stdio: 'ignore',
      })
      killer.on('error', () => {
        try {
          child.kill()
        } catch {
          // The close event still fires and settles the promise.
        }
      })
      return
    }
    // POSIX: runPnpm makes the child a process-group leader, so a negative
    // pid reaches pnpm's own children too.
    if (process.platform !== 'win32' && typeof child.pid === 'number') {
      try {
        process.kill(-child.pid, 'SIGKILL')
        return
      } catch {
        // Fall through to the direct kill.
      }
    }
    child.kill('SIGKILL')
  } catch {
    // The close event still fires and settles the promise.
  }
}

function runPnpm(script, args, cwd, timeoutMs = PNPM_TIMEOUT) {
  return new Promise(resolve => {
    const execPath = nodeRuntime()
    if (execPath === '') {
      resolve({ code: -1, output: 'no node runtime available for pnpm' })
      return
    }
    const env = { ...process.env }
    const invocation = pnpmInvocation(script, args, execPath)
    if (invocation.electron) env.ELECTRON_RUN_AS_NODE = '1'
    const child = spawn(invocation.command, invocation.commandArgs, {
      cwd,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
      // Own process group on POSIX, so killTree can reach the downloaders and
      // build scripts pnpm forks instead of orphaning them.
      detached: process.platform !== 'win32',
    })
    let output = ''
    activePnpmChild = child
    let settled = false
    const collect = chunk => {
      output += String(chunk)
      if (output.length > 40000) output = output.slice(-40000)
    }
    // A hung pnpm would hold every agent's maintenance gate forever; the
    // client-side fetch timeout only abandons the browser side. Kill the
    // child here so the hold is always released.
    const timer = setTimeout(() => {
      output += `\n[pnpm timed out after ${Math.round(timeoutMs / 1000)}s; killing the process tree]`
      killTree(child)
    }, timeoutMs)
    const finish = result => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (activePnpmChild === child) activePnpmChild = null
      resolve(result)
    }
    child.stdout?.on('data', collect)
    child.stderr?.on('data', collect)
    child.on('error', error => {
      finish({ code: -1, output: `${output}\n${error instanceof Error ? error.message : String(error)}` })
    })
    child.on('close', code => {
      finish({ code: typeof code === 'number' ? code : -1, output })
    })
  })
}

/** How long a batch update waits for every agent to go idle before giving up. */
const IDLE_WAIT_MS = 3 * 60 * 1000

/** A batch install rewrites the whole profile store; give it room. */
const BATCH_TIMEOUT = 25 * 60 * 1000

/**
 * One probe of a single package, inside the batch budget.
 *
 * A probe exists to find out *whether* a known-suspect package installs, and a
 * package that cannot install usually says so in the first seconds (404, no
 * matching version, peer conflict). Inheriting the 25-minute batch budget would
 * let one hung registry call eat the whole update.
 */
const SINGLE_TIMEOUT = 90 * 1000

/**
 * How many times the install loop may go back to pnpm.
 *
 * One clean attempt, then one retry per round of blamed packages. Four is
 * enough to peel off a handful of bad packages while keeping the worst case
 * (a broken registry) from turning into a pnpm storm.
 */
const MAX_INSTALL_ROUNDS = 4

/** Up to this many suspects it is cheaper to probe each one than to bisect. */
const MAX_SINGLE_PROBES = 8

/** The tail of a command output: pnpm puts the useful line last. */
const tailOf = (text, max) => (typeof text === 'string' ? text.slice(-max) : '')

/**
 * Permit one exact version through pnpm's supply-chain age policy.
 *
 * The profile carries a `minimumReleaseAgeExclude` list in pnpm-workspace.yaml
 * and pnpm refuses any version younger than the configured minimum release age
 * unless that exact version appears in it. The marketplaces append to this list
 * on every install; an update that skips the step fails on policy, not on the
 * network — which is indistinguishable from "the update is broken" unless you
 * know to look here.
 *
 * Returns true when the document actually changed.
 */
function allowVersion(document, name, version) {
  const key = 'minimumReleaseAgeExclude'
  const prefix = `${name}@`
  const list = document.get(key)
  if (list === undefined || list === null) {
    document.set(key, [`${prefix}${version}`])
    return true
  }
  if (typeof list.add !== 'function') return false
  for (const item of list.items ?? []) {
    const value = typeof item === 'string' ? item : String(item?.value ?? '')
    if (!value.startsWith(prefix)) continue
    const versions = value
      .slice(prefix.length)
      .split('||')
      .map(part => part.trim())
      .filter(part => part.length > 0)
    if (versions.includes(version)) return false
    versions.push(version)
    const next = `${prefix}${versions.join(' || ')}`
    if (typeof item === 'string') return false
    item.value = next
    return true
  }
  list.add(`${prefix}${version}`)
  return true
}

/** Append the raw output of the last update run so a failure can be read later. */
/**
 * Two logs, two jobs:
 * - `last-update.log` is the human-readable narrative of the most recent run,
 *   shown verbatim in the panel when you click "查看日志".
 * - `update-log.jsonl` appends one JSON line per run, forever. It answers the
 *   question "when did this package last fail to update?" without having to
 *   remember which of the last-N runs it was. Rotate by hand if it ever
 *   becomes huge; it is only appended, never read by this plugin.
 */
function writeUpdateLog(title, text) {
  const file = join(stateDir(), 'last-update.log')
  const body = `# ${title} · ${new Date().toISOString()}\n\n${text}\n`
  try {
    mkdirSync(stateDir(), { recursive: true })
    writeFileSync(file, body, 'utf8')
  } catch {
    return null
  }
  try {
    const jsonl = join(stateDir(), 'update-log.jsonl')
    const entry = JSON.stringify({
      at: new Date().toISOString(),
      title,
      ok: !title.startsWith('FAILED'),
    })
    appendFileSync(jsonl, entry + '\n', 'utf8')
  } catch {
    // Append-only history is nice-to-have; the panel log already succeeded.
  }
  return file
}

/**
 * Update every chosen package in ONE pnpm pass.
 *
 * One invocation instead of one per package matters: each `pnpm add` resolves
 * the whole importer graph and re-links the hoisted store (minutes each), so
 * twenty separate calls would take half an hour and multiply the windows in
 * which a failure can happen. A single call resolves and links once.
 *
 * Around it: the supply-chain whitelist is topped up first, the three files
 * pnpm may rewrite are backed up, the run waits for an idle agent instead of
 * refusing, and any failure restores the files and re-syncs node_modules — the
 * host loads from node_modules, so restoring manifests alone would leave the
 * "rolled back" update live.
 */
/**
 * Load freshly installed code without restarting the application. The host's HMR
 * service re-compares every loaded profile module against disk inside its own
 * exclusive transaction and restarts the entries whose files changed — the same
 * path the plugin manager takes when a bundle is toggled.
 *
 * Must not be called from inside an HMR transaction (they cannot nest).
 * Client-half bundles are fetched by the page, so a browser refresh is still
 * needed for those; this only swaps the host-side modules.
 */
async function hotSwapUpdated(ctx) {
  const hmr = ctx.get('hmr')
  if (hmr === undefined || hmr === null || typeof hmr.runReload !== 'function') {
    return { ok: false, reason: 'host HMR service is unavailable' }
  }
  try {
    await hmr.runReload(() => hmr.reconcileProfile())
    return { ok: true }
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : String(error) }
  }
}

/**
 * Which package names does pnpm's failure output actually blame?
 *
 * A batch install fails as one block, and the package it is about is named
 * inside that block — `ERR_PNPM_FETCH_404 GET .../dsh-x/-/dsh-x-1.0.0.tgz`,
 * `No matching version found for dsh-y@9.9.9`. Removing that name and retrying
 * the rest is what turns "8 packages failed, nothing installed" into "7
 * installed, this one did not".
 *
 * A name only counts when it appears on, or within two lines of, an error-ish
 * line. Otherwise a package that merely appears in a progress line would be
 * blamed for someone else's failure — and silently skipped, which is worse than
 * retrying it.
 *
 * Returns [] when nothing can be attributed; callers then probe one by one.
 * Exported for test/batch-fallback.mjs.
 */
export function blamePackages(output, items) {
  if (typeof output !== 'string' || output === '') return []
  const lines = output.split(/\r?\n/)
  const errorish =
    /ERR_PNPM_|EINTEGRITY|ETARGET|404|not found|no matching version|cannot find|could not be resolved|unmet peer|is not in the npm registry|integrity/i
  const hot = []
  for (let index = 0; index < lines.length; index += 1) {
    if (errorish.test(lines[index])) hot.push(index)
  }
  if (hot.length === 0) return []
  const blamed = []
  for (const item of items) {
    const plain = String(item.name)
    // pnpm prints scoped packages percent-encoded in URLs, and it does not
    // always encode the same characters: `@scope%2fpkg` and `%40scope%2fpkg`
    // both occur, so try every spelling before giving up on the name.
    const slashOnly = plain.replace('/', '%2f')
    const fully = slashOnly.replace('@', '%40')
    const needles = [...new Set([plain, slashOnly, fully])]
    let hit = false
    for (const needle of needles) {
      const lowered = needle.toLowerCase()
      for (let index = 0; index < lines.length && !hit; index += 1) {
        if (!lines[index].toLowerCase().includes(lowered)) continue
        hit = hot.some(at => Math.abs(at - index) <= 2)
      }
      if (hit) break
    }
    if (hit) blamed.push(plain)
  }
  return blamed
}

/**
 * Install a set of exact versions, degrading instead of failing as a whole.
 *
 * `pnpm add a b c` is all-or-nothing: one bad package and every package in the
 * batch stays on its old version, with a single "the batch failed" message that
 * names none of them. This loop retries what can still succeed:
 *
 *   1. install everything; on failure, blame the names pnpm printed and retry
 *      the rest (at most MAX_INSTALL_ROUNDS pnpm runs);
 *   2. when no name can be attributed, probe each suspect alone (bounded by
 *      MAX_SINGLE_PROBES and by the caller's budget);
 *   3. stop when the budget or the round cap runs out, and report what was
 *      installed and what was not — never a silent partial state.
 *
 * `install` is injected so this can be tested without pnpm: it receives the
 * batch and a timeout, and resolves { code, output }.
 *
 * Exported for test/batch-fallback.mjs.
 */
export async function installWithFallback(options) {
  const items = Array.isArray(options.items) ? options.items : []
  const install = options.install
  const cancelled = typeof options.cancelled === 'function' ? options.cancelled : () => false
  // 每一轮往 pnpm 递哪几个包，都要让调用方知道：批量安装时界面靠它把「正在转」
  // 的标记跟着轮次推进，而不是从头到尾只有第一行在转。
  const onRound = typeof options.onRound === 'function' ? options.onRound : () => {}
  const budgetMs = Number.isFinite(options.budgetMs) ? options.budgetMs : BATCH_TIMEOUT
  const maxRounds = Number.isFinite(options.rounds) ? options.rounds : MAX_INSTALL_ROUNDS
  const maxProbes = Number.isFinite(options.probes) ? options.probes : MAX_SINGLE_PROBES
  const deadline = Date.now() + budgetMs
  const installed = []
  const failed = []
  let output = ''
  let remaining = items.slice()
  let rounds = 0
  let stopped = false
  // Never hand pnpm a non-positive timeout: a spent budget must still allow the
  // in-flight retry to fail quickly and report, not hang until the outer kill.
  const budget = limit => Math.max(5_000, Math.min(limit, deadline - Date.now()))
  while (remaining.length > 0) {
    if (cancelled()) {
      stopped = true
      break
    }
    rounds += 1
    const batch = remaining
    onRound(batch.map(item => item.name))
    const result = await install(batch, budget(BATCH_TIMEOUT))
    output = typeof result?.output === 'string' ? result.output : ''
    if (result?.code === 0) {
      for (const item of batch) installed.push(item)
      remaining = []
      break
    }
    if (cancelled()) {
      stopped = true
      break
    }
    if (Date.now() >= deadline || rounds >= maxRounds) break
    const blamed = blamePackages(output, batch)
    if (blamed.length > 0) {
      for (const name of blamed) failed.push({ name, output: tailOf(output, 1200) })
      remaining = batch.filter(item => !blamed.includes(item.name))
      continue
    }
    if (batch.length === 1) {
      failed.push({ name: batch[0].name, output: tailOf(output, 1200) })
      remaining = []
      break
    }
    if (batch.length <= maxProbes) {
      for (const item of batch) {
        if (cancelled()) {
          stopped = true
          break
        }
        onRound([item.name])
        const single = await install([item], budget(SINGLE_TIMEOUT))
        if (single?.code === 0) installed.push(item)
        else failed.push({ name: item.name, output: tailOf(typeof single?.output === 'string' ? single.output : '', 1200) })
      }
      remaining = []
    }
    break
  }
  // Whatever never got a turn is a failure, not a silent drop.
  if (!stopped) for (const item of remaining) failed.push({ name: item.name, output: tailOf(output, 1200) })
  return { installed, failed, output, cancelled: stopped }
}
async function applyUpdates(ctx, names, pinned = null, job = null) {
  const facts = profileFacts(ctx)
  if (facts === null) return { ok: false, message: 'profile package.json is unavailable' }
  const script = pnpmScript()
  if (script === null) return { ok: false, message: 'pnpm was not found next to the host' }

  const wanted = Array.isArray(names) ? names.filter(name => typeof name === 'string') : []
  // A queued update remembers the version the user actually agreed to.
  // Re-resolving `latest` minutes later would install a release they never
  // saw, which is exactly the drift this queue is supposed to avoid.
  const pinnedVersions = new Map()
  if (Array.isArray(pinned)) {
    for (const one of pinned) {
      if (one === null || typeof one !== 'object') continue
      if (typeof one.name !== 'string' || typeof one.version !== 'string') continue
      pinnedVersions.set(one.name, one.version)
    }
  }
  const byName = new Map(eligibleDeps(facts).map(entry => [entry.name, entry]))
  const targets = []
  for (const name of wanted) {
    const entry = byName.get(name)
    if (entry !== undefined && !targets.some(item => item.name === name)) targets.push(entry)
  }
  if (targets.length === 0) return { ok: false, message: 'no eligible package to update' }

  const planned = []
  const outOfRange = []
  const registryBase = await configuredRegistry(ctx)
  for (const target of targets) {
    // 每查一个都先看有没有被取消：registry 查询 + 代理重试是弱网下最长的一段，
    // 用户在这段时间点取消，不该白等几十秒再发现后台照样在跑。
    assertNotCancelled(job)
    let latest = pinnedVersions.get(target.name)
    if (latest === undefined) {
      try {
        latest = await npmLatest(target.name, registryBase)
      } catch (error) {
        return { ok: false, message: `${target.name}: ${error instanceof Error ? error.message : String(error)}` }
      }
    }
    if (compareVersions(latest, target.current) <= 0) continue
    // The user's own range is a decision, not an obstacle: `^1.2.3` says 2.x is
    // out of bounds, so installing it because the registry moved on would be
    // this panel overriding them. Report it instead of applying it silently.
    if (target.kind !== 'exact' && !satisfiesSpec(latest, target.spec)) {
      outOfRange.push({ name: target.name, spec: target.spec, latest })
      continue
    }
    planned.push({ name: target.name, current: target.current, latest })
  }
  assertNotCancelled(job)
  if (planned.length === 0) {
    if (outOfRange.length > 0) {
      return {
        ok: true,
        updated: [],
        outOfRange,
        message: outOfRange
          .map(one => `${one.name} ${one.latest} 超出了 package.json 写明的 ${one.spec}，没有安装`)
          .join('；'),
      }
    }
    return { ok: true, updated: [], message: 'already current' }
  }

  // Everything pnpm may touch, kept for the rollback below.
  const backup = new Map()
  for (const file of ['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml']) {
    const full = join(facts.dir, file)
    try {
      backup.set(full, readFileSync(full, 'utf8'))
    } catch {
      // A missing lockfile or workspace file is normal on a fresh profile.
    }
  }

  // Top up the supply-chain whitelist before pnpm ever sees the request.
  let allowed = 0
  let allowNote = null
  const workspaceFile = join(facts.dir, 'pnpm-workspace.yaml')
  try {
    const { yaml } = await patchContext(ctx)
    const document = yaml.parseDocument(readFileSync(workspaceFile, 'utf8'))
    for (const item of planned) if (allowVersion(document, item.name, item.latest)) allowed += 1
    if (allowed > 0) writeFileSync(workspaceFile, document.toString(), 'utf8')
  } catch (error) {
    allowNote = error instanceof Error ? error.message : String(error)
  }

  /**
   * 取消/排队/失败三种提前退出都必须走这里：白名单已经写进 pnpm-workspace.yaml 了，
   * 光 return 会把条目留在用户文件里，下次更新时那些版本就永远被放行。
   * pnpm 一次都没跑过，所以只需要恢复这一份文件。
   */
  const abandonBeforePnpm = () => {
    if (allowed === 0) return
    try {
      for (const [file, text] of backup) writeFileSync(file, text, 'utf8')
    } catch {
      // 写不回去也只能认了：下次更新会重算白名单。
    }
  }

  // Wait for idle instead of making the user retry by hand.
  let release = null
  const deadline = Date.now() + IDLE_WAIT_MS
  for (;;) {
    // 取消检查必须在 holdAgents 之前：用户点取消后这里直接退出，
    // 不能再去抢一次维护门。
    if (jobCancelled(job) || (activeJobAbort !== null && activeJobAbort.signal.aborted)) {
      abandonBeforePnpm()
      throw new Error('cancelled by the user')
    }
    try {
      release = await holdAgents(ctx)
      break
    } catch {
      if (Date.now() >= deadline) {
        abandonBeforePnpm()
        // Nothing was touched; remember the intent so the idle watcher retries
        // it without the user having to babysit the panel.
        enqueueItem({
          kind: 'updates',
          names: planned.map(item => item.name),
          targets: planned.map(item => ({ name: item.name, version: item.latest })),
        })
        return {
          ok: true,
          queued: true,
          message: '会话一直在忙，这次更新先排队；空闲后自动装上',
        }
      }
      await new Promise(resume => setTimeout(resume, 3000))
    }
  }
  // 宿主没有 agents 服务时维护门是空的：更新照样能跑，但**没有**「等所有会话空闲」
  // 这层保护。这件事必须让用户知道，不能和「等过了、都空闲」长得一模一样。
  const unguarded = release !== null && release.gated === false

  // 抢到维护门之后、真正 spawn pnpm 之前，最后再看一次取消。
  if (jobCancelled(job) || (activeJobAbort !== null && activeJobAbort.signal.aborted)) {
    try {
      release()
    } finally {
      abandonBeforePnpm()
    }
    throw new Error('cancelled by the user')
  }

  activeJobStage = 'install'
  // 分轮安装：一轮失败不等于全部失败。peel-off 的规则都在 installWithFallback 里，
  // 这里只负责把 pnpm 的那一次运行接上，并把结果整理成 job 能汇报的形状。
  const installBatch = (batch, timeoutMs) =>
    runPnpm(
      script,
      ['add', ...batch.map(item => `${item.name}@${item.latest}`), '--save-exact', '--prefer-offline'],
      facts.dir,
      timeoutMs,
    )
  let step
  try {
    step = await installWithFallback({
      items: planned,
      install: installBatch,
      cancelled: () => jobCancelled(job),
      // 把「这一轮正在装谁」写进任务本身：面板靠 job.installing 让每一行的版本
      // 徽章跟着轮次转，而不是整批只有一个静态的「9 个插件」。
      onRound: names => {
        if (job === null || typeof job !== 'object') return
        job.installing = Array.isArray(names) ? names.slice() : []
        persistJob(job)
      },
    })
  } finally {
    release()
  }
  const installed = step.installed
  const failures = step.failed
  const cancelledMidway = step.cancelled
  const result = { code: failures.length === 0 && installed.length > 0 ? 0 : -1, output: step.output }

  // 一个都没装上才算整体失败：恢复三个文件、把 node_modules 同步回去。
  // 只要有装上的，就不能整批回滚 —— 那会把已经成功的也一起撤掉。
  if (installed.length === 0) {
    for (const [file, text] of backup) writeFileSync(file, text, 'utf8')
    // node_modules still holds whatever did install, and the host loads from
    // there — restoring the manifests alone would leave the update live.
    // Rolling back is one more pnpm run and can take minutes; say so on the
    // job page instead of leaving it frozen on "install".
    activeJobStage = 'rollback'
    // job.stage 是界面的真实来源：client 靠它把取消按钮摘掉，
    // 否则用户能在回滚跑到一半时把回滚用的 pnpm 也杀掉。
    if (job !== null && typeof job === 'object') job.stage = 'rollback'
    let resync = null
    try {
      const releaseAgain = await holdAgents(ctx)
      try {
        resync = await runPnpm(script, ['install', '--prefer-offline'], facts.dir, BATCH_TIMEOUT)
      } finally {
        releaseAgain()
      }
    } catch {
      // A busy agent is fine: the manifests are restored and the next real
      // install converges node_modules anyway.
    }
    const resyncState = resync === null ? 'skipped' : resync.code === 0 ? 'ok' : 'failed'
    const log = writeUpdateLog(
      `FAILED ${planned.map(item => `${item.name}@${item.latest}`).join(' ')}`,
      [
        `plan: ${planned.map(item => `${item.name} ${item.current} -> ${item.latest}`).join(', ')}`,
        `whitelist entries added: ${allowed}${allowNote === null ? '' : ` (note: ${allowNote})`}`,
        `resync: ${resyncState}`,
        '',
        result.output,
      ].join('\n'),
    )
    return {
      ok: false,
      rolledBack: true,
      updated: [],
      failed:
        failures.length === 0
          ? [{ name: `${planned.length} 个包`, output: tailOf(result.output, 1500) }]
          : failures,
      resync: resyncState,
      log,
      message:
        `批量更新失败，三个文件已回滚（${planned.length} 个包一个都没改动）` +
        (resyncState === 'failed'
          ? '；node_modules 重同步未完成，重启前请再执行一次更新或手动 pnpm install'
          : ''),
    }
  }

  if (cancelledMidway) {
    // 取消发生在已经有包装好之后：保留已装的，不再为了「干净」跑一次回滚。
    activeJobStage = null
    const log = writeUpdateLog(
      `CANCELLED with ${installed.length} package(s) installed`,
      [
        `installed: ${installed.map(item => `${item.name} ${item.current} -> ${item.latest}`).join(', ')}`,
        `not installed: ${failures.map(one => one.name).join(', ')}`,
        '',
        result.output,
      ].join('\n'),
    )
    return {
      ok: true,
      cancelled: true,
      updated: installed.map(item => ({ name: item.name, from: item.current, to: item.latest })),
      failed: failures,
      log,
      message: `已取消：${installed.length} 个包已经装好并保留，其余没有改动`,
    }
  }

  cache.clear()
  // Swap the new code in now instead of asking for a restart. A fresh hold keeps
  // a session from starting while entries are being stopped and restarted.
  let swap = { ok: false, reason: 'no idle moment to swap code' }
  try {
    const releaseSwap = await holdAgents(ctx)
    try {
      swap = await hotSwapUpdated(ctx)
    } finally {
      releaseSwap()
    }
  } catch {
    // A busy agent leaves the restart advice in place.
  }
  const log = writeUpdateLog(
    `OK ${installed.length} package(s)${failures.length === 0 ? '' : `, ${failures.length} failed`}`,
    [
      `updated: ${installed.map(item => `${item.name} ${item.current} -> ${item.latest}`).join(', ')}`,
      `whitelist entries added: ${allowed}`,
      `hot swap: ${swap.ok === true ? 'ok' : swap.reason}`,
      `idle gate: ${unguarded ? 'unavailable (host exposes no agents service)' : 'held'}`,
      '',
      result.output.slice(-4000),
    ].join('\n'),
  )
  // 两条提醒可以同时成立（部分失败 + 没有维护门），拼在一起而不是互相覆盖。
  const notes = []
  if (failures.length > 0) notes.push(`已更新 ${installed.length} 个；${failures.length} 个没装上（见失败详情），它们仍是旧版本`)
  if (unguarded) notes.push('宿主没有 agents 服务：这次没等所有会话空闲就改动了 node_modules')
  return {
    ok: true,
    updated: installed.map(item => ({ name: item.name, from: item.current, to: item.latest })),
    // 部分成功也要如实说：装上了哪些、哪些没装上。
    ...(failures.length > 0 ? { failed: failures, partial: true } : {}),
    // Reported rather than swallowed: the user asked to update these, and the
    // honest answer is "the range you wrote excludes the new version".
    ...(outOfRange.length > 0 ? { outOfRange } : {}),
    hotSwap: swap,
    restart: swap.ok !== true,
    // 没有维护门时如实上报：用户有权知道这次是在会话可能正跑着的时候改了 node_modules。
    ...(unguarded ? { unguarded: true } : {}),
    ...(notes.length > 0 ? { message: notes.join('；') } : {}),
    log,
  }
}
/* ---------------------------- other install kinds ---------------------------- */

const GITHUB_SPEC = /^github:([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:#([^#]*))?$/
const REMOTE_SPEC = /^https?:\/\//

function installedVersion(dir, name) {
  try {
    const parsed = JSON.parse(readFileSync(join(dir, 'node_modules', name, 'package.json'), 'utf8'))
    return typeof parsed.version === 'string' ? parsed.version : null
  } catch {
    return null
  }
}

/** The commit pnpm resolved a `github:` dependency to, read back from the lockfile. */
/**
 * 本地 pin 的 GitHub commit，读不到返回 null。
 *
 * pnpm 把 github 依赖写进 lockfile 的形状不止一种，之前只认
 * `name@https://codeload.github.com/.../tar.gz/<sha>:` 这一种，于是换了安装方式
 * 或 pnpm 版本就读不出来。读不出来的后果很实在：github 行的 hasUpdate 只能
 * 保守地给 false，那一行永远不进更新列表，重新拉取的分支也就一次都跑不到。
 *
 * 已知的几种写法都要认：
 *   name@https://codeload.github.com/owner/repo/tar.gz/<sha>:   （tarball 形式）
 *   'name@github:owner/repo#<sha>':                            （旧式 github spec）
 *   name@github:owner/repo/<sha>                               （另一种分隔）
 * resolution: { commit: <sha>, ... }                           （结构化记录）
 */
function installedCommit(dir, name) {
  let lock
  try {
    lock = readFileSync(join(dir, 'pnpm-lock.yaml'), 'utf8')
  } catch {
    return null
  }
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const patterns = [
    // tarball 形式（最常见）
    new RegExp(`^\\s*${escaped}@https://codeload\\.github\\.com/[^/]+/[^/]+/tar\\.gz/([0-9a-f]{7,40}):`, 'm'),
    // github: 前缀，锚在 # 或 / 之后
    new RegExp(`^\\s*['"]?${escaped}@github:[^#\\s'"]+[#/]([0-9a-f]{7,40})['"]?:?`, 'm'),
    // 结构化记录：包名那一行的块里出现 resolution.commit。不能只搜
    // `resolution: { commit:` —— 那个没有绑定到任何包名，会把别的依赖的
    // commit 当成这个包的，判出完全错误的「已是最新」。
    new RegExp(
      `^\\s*['"]?${escaped}@[^\\n]*:\\s*\\n(?:[ \\t]+[^\\n]*\\n)*?[ \\t]+resolution:\\s*\\{[^}]*commit:\\s*['"]?([0-9a-f]{7,40})`,
      'm',
    ),
  ]
  for (const pattern of patterns) {
    const match = pattern.exec(lock)
    if (match !== null && typeof match[1] === 'string' && match[1] !== '') return match[1]
  }
  return null
}

/**
 * Headers for GitHub's REST API. An unauthenticated caller is capped at 60
 * requests an hour, which a full profile listing can exhaust, so a token from
 * the environment is used when one is present.
 */
function githubHeaders() {
  const headers = { accept: 'application/vnd.github+json', 'user-agent': 'dsh-plugin-rack' }
  const token = typeof process.env.GITHUB_TOKEN === 'string' ? process.env.GITHUB_TOKEN.trim() : ''
  if (token.length > 0) headers.authorization = `Bearer ${token}`
  return headers
}

async function githubHead(owner, repo) {
  const response = await fetchAny(`https://api.github.com/repos/${owner}/${repo}/commits?per_page=1`, {
    signal: AbortSignal.timeout(12000),
    headers: githubHeaders(),
  })
  if (!response.ok) throw new Error(`github answered ${response.status}`)
  const body = await response.json()
  const first = Array.isArray(body) ? body[0] : null
  const commit = first === null || typeof first !== 'object' ? null : first.commit
  if (commit === null || typeof commit !== 'object') throw new Error('github returned no commit')
  const message = typeof commit.message === 'string' ? commit.message.split('\n')[0].slice(0, 140) : null
  const date = commit.committer?.date ?? commit.author?.date ?? null
  return { sha: typeof first.sha === 'string' ? first.sha : null, date, message }
}

/**
 * The latest published GitHub Release of a repository. Used for `file:`
 * installs, where the tarball has no registry entry to compare against, but
 * the project usually still publishes tagged releases we can read a version
 * from. Returns null when the repository publishes no releases at all.
 */
async function githubLatestRelease(owner, repo) {
  const response = await fetchAny(`https://api.github.com/repos/${owner}/${repo}/releases/latest`, {
    signal: AbortSignal.timeout(12000),
    headers: githubHeaders(),
  })
  if (response.status === 404) return null
  if (!response.ok) throw new Error(`github answered ${response.status}`)
  const body = await response.json()
  if (body === null || typeof body !== 'object') return null
  const tag = typeof body.tag_name === 'string' ? body.tag_name.trim() : ''
  return {
    tag,
    version: tag.replace(/^v/, ''),
    url: typeof body.html_url === 'string' ? body.html_url : null,
    publishedAt: typeof body.published_at === 'string' ? body.published_at : null,
  }
}

/**
 * The highest semver tag of a repository. Plenty of projects tag every release
 * without ever publishing a GitHub Release, so `/releases/latest` answers 404
 * for them and their updates would stay invisible; the tags API sees them.
 * Returns null when no tag parses as a version.
 */
async function githubLatestTag(owner, repo) {
  const response = await fetchAny(`https://api.github.com/repos/${owner}/${repo}/tags?per_page=100`, {
    signal: AbortSignal.timeout(12000),
    headers: githubHeaders(),
  })
  if (response.status === 404) return null
  if (!response.ok) throw new Error(`github answered ${response.status}`)
  const body = await response.json()
  if (!Array.isArray(body)) return null
  let best = null
  for (const item of body) {
    const tag = typeof item?.name === 'string' ? item.name.trim() : ''
    const version = tag.replace(/^v/, '')
    if (!EXACT_VERSION.test(version)) continue
    if (best === null || compareVersions(version, best.version) > 0) best = { tag, version }
  }
  if (best === null) return null
  return {
    tag: best.tag,
    version: best.version,
    url: `https://github.com/${owner}/${repo}/releases/tag/${best.tag}`,
    publishedAt: null,
  }
}

/**
 * The newest version a repository advertises, whichever way it advertises it:
 * a published Release, or a bare tag. The two are compared as versions rather
 * than trusted in order, because a project can tag ahead of its last Release.
 */
async function githubBestVersion(owner, repo) {
  const found = []
  const failures = []
  for (const read of [githubLatestRelease, githubLatestTag]) {
    try {
      const one = await read(owner, repo)
      if (one !== null && one.version.length > 0) found.push(one)
    } catch (error) {
      failures.push(error instanceof Error ? error.message : String(error))
    }
  }
  if (found.length === 0) {
    if (failures.length > 0) throw new Error(failures.join('; '))
    return null
  }
  found.sort((left, right) => compareVersions(right.version, left.version))
  return found[0]
}

/**
 * The assets attached to one GitHub Release. Tags without a Release have none,
 * and the API answers 404 for those, so an empty list is a normal answer.
 */
async function githubReleaseAssets(owner, repo, tag) {
  const response = await fetchAny(
    `https://api.github.com/repos/${owner}/${repo}/releases/tags/${encodeURIComponent(tag)}`,
    { signal: AbortSignal.timeout(REGISTRY_TIMEOUT), headers: githubHeaders() },
  )
  if (response.status === 404) return []
  if (!response.ok) throw new Error(`github answered ${response.status}`)
  const body = await response.json()
  const list =
    body !== null && typeof body === 'object' && Array.isArray(body.assets) ? body.assets : []
  return list
    .filter(
      item =>
        item !== null &&
        typeof item === 'object' &&
        typeof item.name === 'string' &&
        typeof item.browser_download_url === 'string',
    )
    .map(item => ({
      name: item.name,
      size: typeof item.size === 'number' ? item.size : null,
      url: item.browser_download_url,
    }))
}

/**
 * The tarball among a release's assets that belongs to this package. Matches by
 * prefix so `dsh-our-free-model` picks `dsh-our-free-model-2.8.3.tgz` and never
 * the macOS `.dmg` or the installer `.exe` sitting next to it.
 */
function pickTarballAsset(assets, name) {
  const bare = name.includes('/') ? name.slice(name.lastIndexOf('/') + 1) : name
  for (const asset of assets) {
    if (asset.name.startsWith(`${bare}-`) && asset.name.endsWith('.tgz')) return asset
  }
  return null
}

/** Read the hash out of a `SHA256SUMS` file for one asset. */
function parseSha256Sums(text, assetName) {
  for (const line of String(text).split(/\r?\n/)) {
    const match = /^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$/.exec(line)
    if (match !== null && match[2] === assetName) return match[1].toLowerCase()
  }
  return null
}

function sha256OfFile(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

/**
 * Download a release asset to a path. Buffered on purpose: release tarballs run
 * tens of megabytes, and a single `arrayBuffer()` avoids a stream wrapper that
 * would have to be kept in step with the hash check right after it.
 */
/**
 * A release asset download is bounded, but generously: these tarballs run tens
 * of megabytes and a slow link really does need minutes (one measured run took
 * 12m for 30 MB). The stall timer is the real guard against a dead socket; this
 * one only stops an endless trickle.
 */
// ---- download transport ---------------------------------------------------
// The asset has to arrive over whatever network the user actually has: a plain
// connection, a corporate HTTP proxy, a local SOCKS5 client (Clash / v2ray), or
// one that comes and goes. So every attempt is resumable, the routes are tried
// from most to least likely, and a route that cannot reach the host falls
// through to the next one instead of failing the whole update.

const DOWNLOAD_TIMEOUT_MS = 30 * 60 * 1000
const DOWNLOAD_STALL_MS = 30 * 1000
const DOWNLOAD_TRIES = 3
const DOWNLOAD_REDIRECTS = 5
const DOWNLOAD_CONNECT_MS = 20 * 1000

/** "host:port", "http://host:port", "socks5://user:pass@host:port" -> route. */
function parseProxy(value) {
  if (typeof value !== 'string') return null
  let text = value.trim()
  if (text === '') return null
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) text = 'http://' + text
  let parsed
  try {
    parsed = new URL(text)
  } catch (error) {
    void error
    return null
  }
  const protocol = parsed.protocol.toLowerCase()
  const kind =
    protocol === 'socks5:' || protocol === 'socks5h:' || protocol === 'socks4:'
      ? 'socks'
      : protocol === 'http:' || protocol === 'https:'
        ? 'http'
        : null
  if (kind === null) return null
  const port = Number(parsed.port === '' ? (kind === 'http' ? 80 : 1080) : parsed.port)
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null
  if (parsed.hostname === '') return null
  const auth =
    parsed.username === ''
      ? null
      : { user: decodeURIComponent(parsed.username), pass: decodeURIComponent(parsed.password ?? '') }
  return { kind, protocol, host: parsed.hostname, port, auth, label: parsed.hostname + ':' + port }
}

function noProxyMatch(host, raw) {
  if (typeof raw !== 'string' || raw.trim() === '') return false
  for (const entry of raw.split(',')) {
    const one = entry.trim().toLowerCase()
    if (one === '') continue
    if (one === '*') return true
    const bare = one.startsWith('.') ? one.slice(1) : one
    const name = host.toLowerCase()
    if (name === bare || name.endsWith('.' + bare)) return true
  }
  return false
}

/**
 * Whether Windows is actually routing through that proxy right now.
 *
 * The ProxyServer value stays in the registry after the user turns the proxy
 * off — only ProxyEnable flips. Reading ProxyServer alone therefore sends every
 * download into a dead port and burns the whole timeout budget before the direct
 * fallback even starts; that is the "tried 127.0.0.1:7900 … direct: The
 * operation was aborted" report. A missing ProxyEnable counts as enabled,
 * because older layouts only wrote ProxyServer.
 */
function proxyEnableAllows(stdout) {
  if (typeof stdout !== 'string') return true
  const match = /ProxyEnable\s+REG_DWORD\s+0x([0-9a-fA-F]+)/.exec(stdout)
  if (match === null) return true
  return Number.parseInt(match[1], 16) !== 0
}

/** The proxy Windows itself is configured with, when it is switched on. */
function systemProxyRoute() {
  if (process.platform !== 'win32') return null
  try {
    const key = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'
    // One query for the whole key: ProxyEnable only exists as a sibling value.
    const query = spawnSync('reg', ['query', key], {
      encoding: 'utf8',
      timeout: 3000,
      windowsHide: true,
    })
    if (query.status !== 0 || typeof query.stdout !== 'string') return null
    if (!proxyEnableAllows(query.stdout)) return null
    const match = /ProxyServer\s+REG_SZ\s+(.+)/.exec(query.stdout)
    if (match === null) return null
    const parts = match[1]
      .trim()
      .split(';')
      .map(one => one.trim())
      .filter(one => one !== '')
    const httpsPart = parts.find(one => one.toLowerCase().startsWith('https='))
    const httpPart = parts.find(one => one.toLowerCase().startsWith('http='))
    const chosen = (httpsPart ?? httpPart ?? parts[0] ?? '').replace(/^[a-z]+=/i, '')
    return parseProxy(chosen)
  } catch (error) {
    void error
    return null
  }
}

/**
 * Where to try, in order: an explicit choice from config.json, then the
 * environment, then the system proxy, then the plain connection. NO_PROXY and an
 * unreachable proxy both degrade to the next entry instead of failing.
 */
function downloadRoutes(url) {
  const target = url instanceof URL ? url : new URL(url)
  const routes = []
  const add = (label, route) => {
    if (route !== null && routes.some(one => one.route !== null && one.route.host === route.host && one.route.port === route.port)) return
    routes.push({ label, route })
  }
  let mode = 'auto'
  try {
    const parsed = JSON.parse(readFileSync(join(stateDir(), 'config.json'), 'utf8'))
    const download = parsed !== null && typeof parsed === 'object' && parsed.download !== null && typeof parsed.download === 'object' ? parsed.download : null
    if (download !== null && typeof download.proxy === 'string' && download.proxy.trim() !== '') mode = download.proxy.trim()
  } catch (error) {
    void error
  }
  if (mode === 'off' || mode === 'direct' || mode === 'none') {
    add('direct', null)
    return routes
  }
  // A host on this machine is not reachable through a proxy and a CONNECT to it
  // stalls. Only auto-detected routes are dropped: a proxy the user configured by
  // hand is honoured even for a local address (that is how the code is tested).
  const skip =
    (mode === 'auto' && isLocalHost(target.hostname)) ||
    noProxyMatch(target.hostname, process.env.NO_PROXY ?? process.env.no_proxy)
  if (mode !== 'auto') {
    const explicit = parseProxy(mode)
    if (explicit !== null && !skip) add(explicit.label, explicit)
  } else {
    const env =
      process.env.HTTPS_PROXY ??
      process.env.https_proxy ??
      process.env.ALL_PROXY ??
      process.env.all_proxy ??
      process.env.HTTP_PROXY ??
      process.env.http_proxy
    const fromEnv = parseProxy(env ?? '')
    if (fromEnv !== null && !skip) add(fromEnv.label, fromEnv)
    const system = systemProxyRoute()
    if (system !== null && !skip) add(system.label, system)
  }
  add('direct', null)
  return routes
}

/** Hosts only this machine can reach — a proxy could only stall on them. */
function isLocalHost(hostname) {
  const host = hostname.toLowerCase()
  if (host === 'localhost' || host === '::1' || host === '[::1]' || host.endsWith('.localhost')) return true
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)
  if (v4 === null) return false
  const first = Number(v4[1])
  const second = Number(v4[2])
  if (first === 127 || first === 10) return true
  if (first === 192 && second === 168) return true
  if (first === 172 && second >= 16 && second <= 31) return true
  return first === 169 && second === 254
}

function connectTcp(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host, port })
    const timer = setTimeout(() => {
      socket.destroy()
      reject(new Error('连接 ' + host + ':' + port + ' 超时'))
    }, timeoutMs)
    socket.once('error', error => {
      clearTimeout(timer)
      reject(error)
    })
    socket.once('connect', () => {
      clearTimeout(timer)
      socket.removeAllListeners('error')
      socket.on('error', () => {})
      resolve(socket)
    })
  })
}

/** Read up to the blank line, leaving any extra bytes on the socket. */
function readHead(socket, timeoutMs) {
  return new Promise((resolve, reject) => {
    let text = ''
    let done = false
    const finish = (error, head, rest) => {
      if (done) return
      done = true
      clearTimeout(timer)
      socket.removeListener('data', onData)
      socket.removeListener('error', onError)
      socket.removeListener('close', onClose)
      if (error !== null) {
        socket.destroy()
        reject(error)
        return
      }
      if (rest !== undefined && rest.length > 0) socket.unshift(rest)
      resolve(head)
    }
    const timer = setTimeout(() => finish(new Error('代理没有回应')), timeoutMs)
    const onData = chunk => {
      text += chunk.toString('utf8')
      const end = text.indexOf('\r\n\r\n')
      if (end < 0) {
        if (text.length > 65536) finish(new Error('代理响应异常'))
        return
      }
      finish(null, text.slice(0, end), Buffer.from(text.slice(end + 4), 'utf8'))
    }
    const onError = error => finish(error)
    const onClose = () => finish(new Error('代理断开了连接'))
    socket.on('data', onData)
    socket.once('error', onError)
    socket.once('close', onClose)
  })
}

/** Read exactly `count` bytes of a SOCKS5 reply, leaving the rest on the socket. */
function readSocks(socket, count, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0)
    let done = false
    const finish = (error, all) => {
      if (done) return
      done = true
      clearTimeout(timer)
      socket.removeListener('data', onData)
      socket.removeListener('error', onError)
      if (error !== null) {
        socket.destroy()
        reject(error)
        return
      }
      if (all.length > count) socket.unshift(all.subarray(count))
      resolve(all.subarray(0, count))
    }
    const timer = setTimeout(() => finish(new Error('SOCKS 代理没有回应')), timeoutMs)
    const onData = chunk => {
      buffer = Buffer.concat([buffer, chunk])
      if (buffer.length >= count) finish(null, buffer)
    }
    const onError = error => finish(error)
    socket.on('data', onData)
    socket.once('error', onError)
  })
}

async function socksOpen(socket, route, host, port) {
  socket.write(route.auth === null ? Buffer.from([0x05, 0x01, 0x00]) : Buffer.from([0x05, 0x02, 0x00, 0x02]))
  const pick = await readSocks(socket, 2, DOWNLOAD_CONNECT_MS)
  if (pick[0] !== 0x05) throw new Error('代理不是 SOCKS5')
  if (pick[1] === 0xff) throw new Error('代理不接受可用的认证方式')
  if (pick[1] === 0x02) {
    if (route.auth === null) throw new Error('代理要求用户名和密码')
    const user = Buffer.from(route.auth.user, 'utf8')
    const pass = Buffer.from(route.auth.pass, 'utf8')
    socket.write(Buffer.concat([Buffer.from([0x01, user.length]), user, Buffer.from([pass.length]), pass]))
    const answer = await readSocks(socket, 2, DOWNLOAD_CONNECT_MS)
    if (answer[1] !== 0x00) throw new Error('代理拒绝了用户名和密码')
  }
  const name = Buffer.from(host, 'utf8')
  socket.write(
    Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, name.length]), name, Buffer.from([port >> 8, port & 0xff])]),
  )
  const reply = await readSocks(socket, 4, DOWNLOAD_CONNECT_MS)
  if (reply[1] !== 0x00) throw new Error('代理拒绝连到目标主机 (' + reply[1] + ')')
  if (reply[3] === 0x01) await readSocks(socket, 6, DOWNLOAD_CONNECT_MS)
  else if (reply[3] === 0x04) await readSocks(socket, 18, DOWNLOAD_CONNECT_MS)
  else if (reply[3] === 0x03) {
    const length = await readSocks(socket, 1, DOWNLOAD_CONNECT_MS)
    await readSocks(socket, length[0] + 2, DOWNLOAD_CONNECT_MS)
  }
}

/** A socket that already speaks to `host:port`, through the proxy or directly. */
async function openTunnel(route, host, port) {
  const socket = await connectTcp(route.host, route.port, DOWNLOAD_CONNECT_MS)
  try {
    if (route.kind === 'socks') {
      await socksOpen(socket, route, host, port)
      return socket
    }
    const auth =
      route.auth === null
        ? ''
        : 'Proxy-Authorization: Basic ' +
          Buffer.from(route.auth.user + ':' + route.auth.pass).toString('base64') +
          '\r\n'
    socket.write(
      'CONNECT ' + host + ':' + port + ' HTTP/1.1\r\nHost: ' + host + ':' + port + '\r\n' + auth + '\r\n',
    )
    const head = await readHead(socket, DOWNLOAD_CONNECT_MS)
    const status = Number((head.split('\r\n')[0] ?? '').split(' ')[1] ?? 0)
    if (status !== 200) throw new Error('代理拒绝建立隧道 (' + status + ')')
    return socket
  } catch (error) {
    socket.destroy()
    throw error
  }
}

function openStream(route, url, offset, signal) {
  const isTls = url.protocol === 'https:'
  const port = Number(url.port === '' ? (isTls ? 443 : 80) : url.port)
  const headers = { ...githubHeaders(), 'accept-encoding': 'identity' }
  if (offset > 0) headers.range = 'bytes=' + offset + '-'
  return new Promise((resolve, reject) => {
    const start = async () => {
      let socket = null
      if (route !== null) socket = await openTunnel(route, url.hostname, port)
      const options = {
        method: 'GET',
        host: url.hostname,
        port,
        path: url.pathname + url.search,
        headers,
      }
      if (signal !== undefined && signal !== null) options.signal = signal
      if (socket !== null && isTls) {
        const secure = tlsConnect({ socket, servername: url.hostname })
        await new Promise((resolveHandshake, rejectHandshake) => {
          secure.once('secureConnect', resolveHandshake)
          secure.once('error', rejectHandshake)
        })
        options.createConnection = () => secure
      } else if (socket !== null) {
        options.createConnection = () => socket
      }
      const request = (isTls ? httpsRequest : httpRequest)(options, response => resolve(response))
      request.on('error', reject)
      request.end()
    }
    start().catch(reject)
  })
}

async function pipeTo(part, response, signal, offset, deadline) {
  const stream = createWriteStream(part, { flags: offset > 0 ? 'a' : 'w' })
  // A write error used to reach nobody: the stream emitted 'error' with no
  // listener, an unhandled 'error' takes the whole process down, and this
  // plugin shares the host's process. Remember the failure here instead, and
  // keep the listener for as long as the stream can still emit.
  let failure = null
  stream.on('error', error => {
    if (failure === null) failure = error
  })

  let idle = null
  const arm = () => {
    if (idle !== null) clearTimeout(idle)
    idle = setTimeout(
      () => response.destroy(new Error('下载卡住：' + Math.round(DOWNLOAD_STALL_MS / 1000) + ' 秒没有收到数据')),
      DOWNLOAD_STALL_MS,
    )
  }
  const onAbort = () => response.destroy(new Error('cancelled'))
  // Wait for the write buffer to drain, but stop waiting on abort or error:
  // a stalled disk plus a cancel would otherwise sit here forever.
  const waitDrain = () =>
    new Promise((resolve, reject) => {
      const done = () => {
        clean()
        resolve(undefined)
      }
      const failDrain = error => {
        clean()
        reject(error)
      }
      const onSignal = () => {
        response.destroy(new Error('cancelled'))
        failDrain(new Error('cancelled'))
      }
      const clean = () => {
        stream.removeListener('drain', done)
        stream.removeListener('error', failDrain)
        if (signal !== undefined && signal !== null) signal.removeEventListener('abort', onSignal)
      }
      stream.once('drain', done)
      stream.once('error', failDrain)
      if (signal !== undefined && signal !== null) {
        if (signal.aborted) {
          onSignal()
          return
        }
        signal.addEventListener('abort', onSignal, { once: true })
      }
    })
  if (signal !== undefined && signal !== null) {
    if (signal.aborted) onAbort()
    else signal.addEventListener('abort', onAbort, { once: true })
  }
  try {
    arm()
    for await (const chunk of response) {
      if (failure !== null) throw failure
      if (Date.now() >= deadline) {
        const late = new Error('下载超过 ' + Math.round(DOWNLOAD_TIMEOUT_MS / 60000) + ' 分钟，已放弃')
        response.destroy(late)
        throw late
      }
      arm()
      // Honour backpressure: ignoring write()'s answer means the whole
      // attachment piles up in memory while the disk lags.
      if (!stream.write(chunk)) await waitDrain()
      if (failure !== null) throw failure
    }
    await new Promise((resolve, reject) => {
      stream.once('error', reject)
      stream.end(() => resolve(undefined))
    })
  } finally {
    if (idle !== null) clearTimeout(idle)
    if (signal !== undefined && signal !== null) signal.removeEventListener('abort', onAbort)
    // Only tear the stream down after a failure. On success end() has flushed
    // it already, and destroy() would race the last pending write callback
    // with ERR_STREAM_DESTROYED — the other half of the crash above.
    if (failure !== null && !stream.destroyed) stream.destroy()
  }
}

async function fetchToFile(url, part, route, signal, deadline) {
  let target = url instanceof URL ? url : new URL(url)
  for (let hop = 0; hop <= DOWNLOAD_REDIRECTS; hop += 1) {
    const offset = existsSync(part) ? statSync(part).size : 0
    const response = await openStream(route, target, offset, signal)
    const status = response.statusCode ?? 0
    if (status >= 300 && status < 400 && typeof response.headers.location === 'string' && response.headers.location !== '') {
      response.resume()
      target = new URL(response.headers.location, target)
      continue
    }
    if (status !== 200 && status !== 206) {
      response.resume()
      throw new Error('下载被拒绝 (' + status + ')')
    }
    await pipeTo(part, response, signal, status === 206 ? offset : 0, deadline)
    return statSync(part).size
  }
  throw new Error('重定向次数过多')
}

/**
 * Download `url` into `dest`, resuming whatever the last attempt left behind.
 *
 * `dest.part` is the working file: an interrupted run keeps it, so the next
 * attempt — or the next click, minutes later — asks for the remaining bytes with
 * a Range header instead of starting the whole thing over.
 */
/** Exported for test/download.mjs; the host calls it through applyFileUpgrade. */
/**
 * Fetch that survives a proxy-only network.
 *
 * Node's global fetch ignores every proxy setting, which is fine for a normal
 * connection and useless behind a corporate proxy or a local Clash/v2ray client.
 * So a failed fetch is retried over the same routes the asset downloader knows:
 * explicit config, environment, system proxy, then a direct socket.
 */
async function readResponseLike(target, route, signal) {
  let current = target
  for (let hop = 0; hop <= 3; hop += 1) {
    const response = await openStream(route, current, 0, signal)
    const status = response.statusCode ?? 0
    if (status >= 300 && status < 400 && typeof response.headers.location === 'string' && response.headers.location !== '') {
      response.resume()
      current = new URL(response.headers.location, current)
      continue
    }
    const chunks = []
    let total = 0
    for await (const chunk of response) {
      total += chunk.length
      if (total > 8 * 1024 * 1024) {
        response.destroy()
        throw new Error('响应超过 8 MB')
      }
      chunks.push(chunk)
    }
    const body = Buffer.concat(chunks, total).toString('utf8')
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => body,
      json: async () => JSON.parse(body),
    }
  }
  throw new Error('重定向次数过多')
}

/** Exported for test/download.mjs, like downloadFile. */
export async function fetchAny(url, init) {
  try {
    return await fetch(url, init)
  } catch (error) {
    const target = new URL(url)
    const routes = downloadRoutes(target)
    const failures = []
    for (const route of routes) {
      try {
        // A fresh budget per route: the caller's signal is usually a
        // AbortSignal.timeout(...) that the failed fetch has already spent, so
        // passing it on would abort every fallback instantly and report "The
        // operation was aborted" for a route that was never actually tried.
        const fallback = AbortSignal.timeout(REGISTRY_TIMEOUT)
        return await readResponseLike(target, route.route, fallback)
      } catch (next) {
        failures.push(route.label + ': ' + (next instanceof Error ? next.message : String(next)))
      }
    }
    const detail = failures.length === 0 ? '' : ` (tried ${failures.join('; ')})`
    throw new Error((error instanceof Error ? error.message : String(error)) + detail)
  }
}

export async function downloadFile(url, dest, outer) {
  const part = dest + '.part'
  const deadline = Date.now() + DOWNLOAD_TIMEOUT_MS
  const routes = downloadRoutes(url)
  let lastError = null
  for (const route of routes) {
    for (let attempt = 1; attempt <= DOWNLOAD_TRIES; attempt += 1) {
      if (Date.now() >= deadline) throw new Error('下载超过 ' + Math.round(DOWNLOAD_TIMEOUT_MS / 60000) + ' 分钟，已放弃')
      if (outer !== undefined && outer !== null && outer.aborted) throw new Error('cancelled')
      try {
        const bytes = await fetchToFile(url, part, route.route, outer, deadline)
        if (bytes === 0) throw new Error('下载得到空文件')
        renameSync(part, dest)
        return bytes
      } catch (error) {
        if (outer !== undefined && outer !== null && outer.aborted) throw error
        lastError = new Error((route.label === 'direct' ? '' : route.label + ': ') + (error instanceof Error ? error.message : String(error)))
        // Nothing arrived over this route: no point retrying it, try the next.
        if (!existsSync(part) || statSync(part).size === 0) break
        await new Promise(resolve => setTimeout(resolve, 800 * attempt))
      }
    }
  }
  throw lastError ?? new Error('下载失败')
}
/**
 * owner/repo of an installed package, read from the `repository` field of the
 * package that is actually on disk. Works for any install kind, which is what
 * a `file:` dependency needs: its profile spec carries no repository at all.
 */
function repoOf(dir, name) {
  const found = readManifest(name, dir)
  if (found === null) return null
  const links = linksOf(found.manifest)
  if (typeof links.github !== 'string') return null
  const match = /^https:\/\/github\.com\/([^/]+)\/([^/]+)$/.exec(links.github)
  if (match === null) return null
  return { owner: match[1], repo: match[2] }
}

/**
 * Dependencies the exact-version updater deliberately ignores, with a preview
 * for each so the decision is informed: a GitHub install is compared commit to
 * commit, a registry tarball against the package's published latest.
 */
async function listExtras(ctx) {
  const facts = profileFacts(ctx)
  if (facts === null) return { ok: false, message: 'profile package.json is unavailable' }
  const registryBase = await configuredRegistry(ctx)
  const rows = []
  for (const [name, raw] of Object.entries(facts.deps)) {
    if (HOST_SCOPE.test(name)) continue
    const spec = typeof raw === 'string' ? raw.trim() : ''
    // Everything the version updater understands is not an "other install kind":
    // ranges used to land here as `other` rows that offered no action at all.
    if (isVersionSpec(spec)) continue
    const current = installedVersion(facts.dir, name)
    if (spec.startsWith('link:')) {
      rows.push({ name, kind: 'link', spec, current, note: '本地软链' })
      continue
    }
    if (spec.startsWith('github:')) {
      const match = GITHUB_SPEC.exec(spec)
      const installed = installedCommit(facts.dir, name)
      const row = {
        name,
        kind: 'github',
        spec,
        current,
        installedCommit: installed,
        head: null,
        error: null,
        // 客户端按 hasUpdate 决定一个包要不要进「全部更新」的勾选集。github 行
        // 之前没有这个字段，于是它永远进不了 picked，repull 分支一次都跑不到。
        // 判据和徽章按钮用的完全一致：远端 head 与本地 pin 的 commit 不同。
        hasUpdate: false,
      }
      if (match === null) row.error = '无法解析 github 地址'
      else {
        try {
          row.head = await githubHead(match[1], match[2])
          // 只有确实读到了本地 pin 的 commit 才谈得上「有没有更新」。installedCommit()
          // 的正则只认 codeload tarball 那一种 lockfile 写法，读到 null 是常见的
          // （换了安装方式、lockfile 写法不同）。这时候把 head 当作可更新依据，
          // 会让这一行每次都被判成"有新版"，一次全选就重拉一遍。
          if (
            installed !== null &&
            row.head !== null &&
            typeof row.head.sha === 'string' &&
            row.head.sha !== ''
          ) {
            row.hasUpdate = installed !== row.head.sha
          }
        } catch (error) {
          row.error = error instanceof Error ? error.message : String(error)
        }
      }
      rows.push(row)
      continue
    }
    if (REMOTE_SPEC.test(spec)) {
      const row = { name, kind: 'tarball', spec, current, npmLatest: null, hasUpdate: false, error: null }
      try {
        row.npmLatest = await npmLatest(name, registryBase)
        row.hasUpdate = compareVersions(row.npmLatest, current ?? '0.0.0') > 0
      } catch (error) {
        row.error = error instanceof Error ? error.message : String(error)
      }
      rows.push(row)
      continue
    }
    if (spec.startsWith('file:')) {
      // 本地压缩包（例如下载好放进 vendor/ 的那个）：profile 里没有远端地址，
      // 所以改从「已经装着的那个包自己的 repository 字段」找回仓库，再去读它的
      // GitHub 版本号来比对 —— 已发布的 Release 和裸 tag 都算，因为不少项目只打
      // tag 不发 Release。没有仓库、也读不到版本，就只报本地版本。
      const row = { name, kind: 'file', spec, current, latestRelease: null, hasUpdate: false, error: null }
      const repo = repoOf(facts.dir, name)
      if (repo !== null) {
        try {
          const release = await githubBestVersion(repo.owner, repo.repo)
          if (release !== null && release.version !== '') {
            row.latestRelease = release
            row.hasUpdate = compareVersions(release.version, current ?? '0.0.0') > 0
          }
        } catch (error) {
          row.error = error instanceof Error ? error.message : String(error)
        }
      }
      rows.push(row)
      continue
    }
    rows.push({ name, kind: 'other', spec, current })
  }
  return { ok: true, rows }
}

/** Run one pnpm mutation under a maintenance hold, rolling back on failure. */
async function guardedPnpm(ctx, facts, script, args) {
  const backup = new Map()
  for (const file of ['package.json', 'pnpm-lock.yaml']) {
    const full = join(facts.dir, file)
    try {
      backup.set(full, readFileSync(full, 'utf8'))
    } catch {
      // Absent lockfile is normal.
    }
  }
  activeJobStage = 'install'
  let release
  try {
    release = await holdAgents(ctx)
  } catch {
    return { ok: false, waiting: true, message: '有会话正在运行，等它结束后再试' }
  }
  let outcome
  try {
    outcome = await runPnpm(script, args, facts.dir)
  } finally {
    release()
  }
  // 宿主没有 agents 服务时维护门是空的：能装，但没等会话空闲。
  const unguarded = release !== null && release.gated === false
  if (outcome.code !== 0) {
    for (const [file, text] of backup) writeFileSync(file, text, 'utf8')
    // 失败分支也要标：用户看到"回滚了"时要能分清这次到底有没有等会话空闲，
    // 否则靠它判断"能不能安全地立刻重试"就少了一条信息。
    return markUnguarded(
      {
        ok: false,
        rolledBack: true,
        output: outcome.output.slice(-1500),
        message: '安装失败，package.json 与 pnpm-lock.yaml 已回滚',
      },
      unguarded,
    )
  }
  cache.clear()
  // The same swap the batch updater performs, so an extra install also goes live
  // now instead of waiting for a restart.
  let swap = { ok: false, reason: 'no idle moment to swap code' }
  try {
    const releaseSwap = await holdAgents(ctx)
    try {
      swap = await hotSwapUpdated(ctx)
    } finally {
      releaseSwap()
    }
  } catch {
    // A busy agent leaves the restart advice in place.
  }
  return markUnguarded(
    { ok: true, output: outcome.output.slice(-800), hotSwap: swap, restart: swap.ok !== true },
    unguarded,
  )
}

/**
 * What a `file:` dependency would upgrade to — read-only, changes nothing.
 *
 * A local tarball has no registry to ask, so the answer comes from the repo the
 * installed package itself declares: its newest GitHub version, the tarball
 * asset attached to that release, and the official SHA256SUMS entry for it. The
 * hash is what makes this safe, so an upgrade with no published hash is refused
 * instead of installing a file nobody can verify.
 */
async function planFileUpgrade(ctx, name) {
  const facts = profileFacts(ctx)
  if (facts === null) return { ok: false, message: 'profile package.json is unavailable' }
  const spec = typeof facts.deps[name] === 'string' ? facts.deps[name].trim() : ''
  if (!spec.startsWith('file:')) return { ok: false, message: '不是本地文件包' }
  const repo = repoOf(facts.dir, name)
  if (repo === null) return { ok: false, message: '这个包没有声明 GitHub 仓库，找不到官方发布页' }
  const release = await githubBestVersion(repo.owner, repo.repo)
  if (release === null || release.version === '') return { ok: false, message: '读不到官方版本号' }
  const current = installedVersion(facts.dir, name)
  if (current !== null && compareVersions(release.version, current) <= 0) {
    return {
      ok: false,
      message: `官方最新版本 ${release.version} 不高于已安装的 ${current}，无需升级`,
    }
  }
  const assets = await githubReleaseAssets(repo.owner, repo.repo, release.tag)
  const tarball = pickTarballAsset(assets, name)
  if (tarball === null) {
    return {
      ok: false,
      message: `${release.tag} 里没有 ${name} 的压缩包附件（只打 tag 不发 Release 的项目无法自动升级）`,
    }
  }
  const sums = assets.find(asset => asset.name === 'SHA256SUMS')
  if (sums === undefined) {
    return { ok: false, message: `${release.tag} 没有提供 SHA256SUMS，无法校验，已拒绝自动升级` }
  }
  const response = await fetchAny(sums.url, {
    signal: AbortSignal.timeout(REGISTRY_TIMEOUT),
    headers: githubHeaders(),
    redirect: 'follow',
  })
  if (!response.ok) throw new Error(`github answered ${response.status}`)
  const sha256 = parseSha256Sums(await response.text(), tarball.name)
  if (sha256 === null) {
    return { ok: false, message: `SHA256SUMS 里没有 ${tarball.name} 这一条，已拒绝自动升级` }
  }
  return {
    ok: true,
    name,
    current,
    spec,
    nextSpec: `file:./vendor/${tarball.name}`,
    target: {
      tag: release.tag,
      version: release.version,
      releaseUrl: release.url,
      publishedAt: release.publishedAt ?? null,
      asset: { name: tarball.name, size: tarball.size, url: tarball.url },
      sha256,
    },
  }
}

/**
 * Upgrade a `file:` dependency to the tarball on its newest official release.
 *
 * The file is verified before it is ever referenced: it lands as `<name>.part`,
 * the official SHA256SUMS entry is checked against it, and only then does it
 * take its real name and get written into package.json. Any failure after that
 * point restores both manifests and re-syncs node_modules, so "failed" never
 * means "half installed".
 */
async function applyFileUpgrade(ctx, name) {
  const facts = profileFacts(ctx)
  if (facts === null) return { ok: false, message: 'profile package.json is unavailable' }
  const script = pnpmScript()
  if (script === null) return { ok: false, message: 'pnpm was not found next to the host' }

  let manifest
  try {
    manifest = JSON.parse(readFileSync(facts.file, 'utf8'))
  } catch (error) {
    return { ok: false, message: error instanceof Error ? error.message : String(error) }
  }
  if (
    manifest === null ||
    typeof manifest !== 'object' ||
    manifest.dependencies === null ||
    typeof manifest.dependencies !== 'object'
  ) {
    return { ok: false, message: 'profile package.json 里没有 dependencies' }
  }

  let plan
  try {
    plan = await planFileUpgrade(ctx, name)
  } catch (error) {
    return { ok: false, message: error instanceof Error ? error.message : String(error) }
  }
  if (plan.ok !== true) return plan

  const vendor = join(facts.dir, 'vendor')
  try {
    mkdirSync(vendor, { recursive: true })
  } catch {
    // Already there, or the write below reports it.
  }
  const target = join(vendor, plan.target.asset.name)
  const partial = `${target}.part`
  const lockPath = join(facts.dir, 'pnpm-lock.yaml')
  const before = new Map()
  for (const file of [facts.file, lockPath]) {
    try {
      before.set(file, readFileSync(file))
    } catch {
      // A missing lockfile is fine: there is nothing to put back.
    }
  }

  let bytes = 0
  activeJobStage = 'download'
  try {
    // A previous attempt may already have fetched and verified this very asset.
    // Reusing it turns a 12-minute retry into an instant one, and the sha256 of
    // the file on disk is the proof it is the official tarball.
    if (existsSync(target) && sha256OfFile(target) === plan.target.sha256) {
      bytes = statSync(target).size
    } else {
      bytes = await downloadFile(plan.target.asset.url, partial, activeJobAbort === null ? undefined : activeJobAbort.signal)
      const actual = sha256OfFile(partial)
      if (actual !== plan.target.sha256) {
        throw new Error(`官方 sha256 是 ${plan.target.sha256}，下下来的是 ${actual}`)
      }
      renameSync(partial, target)
    }
  } catch (error) {
    // A cancelled run keeps the resume file: the next click finishes it instead
    // of fetching 30 MB again. Any other failure starts clean.
    const cancelled = error instanceof Error && /cancel/i.test(error.message)
    try {
      if (existsSync(partial)) unlinkSync(partial)
      const resume = partial + '.part'
      if (!cancelled && existsSync(resume)) unlinkSync(resume)
    } catch {
      // Best effort: a stray .part is inert.
    }
    return {
      ok: false,
      message: `下载或校验失败，什么都没改：${error instanceof Error ? error.message : String(error)}`,
    }
  }

  activeJobStage = 'install'
  let release
  try {
    release = await holdAgents(ctx)
  } catch {
    // The verified tarball stays on disk and the entry joins the queue: the
    // idle watcher installs it as soon as every Agent is between turns.
    enqueueItem({ kind: 'extras', name, action: 'file-upgrade' })
    return {
      ok: true,
      queued: true,
      message: '附件已下载并校验，先排队；会话一空闲就自动装上',
    }
  }
  // 宿主没有 agents 服务时维护门是空的：能装，但没有「等会话空闲」这层保护。
  const unguarded = release !== null && release.gated === false

  let outcome = null
  try {
    manifest.dependencies[name] = plan.nextSpec
    writeFileSync(facts.file, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
    outcome = await runPnpm(script, ['install', '--prefer-offline'], facts.dir, BATCH_TIMEOUT)
  } catch (error) {
    outcome = { code: -1, output: error instanceof Error ? error.message : String(error) }
  } finally {
    release()
  }

  if (outcome === null || outcome.code !== 0) {
    for (const [file, content] of before) {
      try {
        writeFileSync(file, content)
      } catch {
        // Keep going: restoring the lockfile matters more than the manifest.
      }
    }
    let resync = null
    try {
      const releaseAgain = await holdAgents(ctx)
      try {
        resync = await runPnpm(script, ['install', '--prefer-offline'], facts.dir, BATCH_TIMEOUT)
      } finally {
        releaseAgain()
      }
    } catch {
      resync = null
    }
    try {
      if (existsSync(target)) unlinkSync(target)
    } catch {
      // Best effort.
    }
    const resyncState = resync === null ? 'skipped' : resync.code === 0 ? 'ok' : 'failed'
    writeUpdateLog(
      `FAILED ${name}`,
      `action: file-upgrade\nplan: ${plan.current} -> ${plan.target.version}\nresync: ${resyncState}\n\n${outcome === null ? '' : outcome.output}`,
    )
    return {
      ok: false,
      rolledBack: true,
      resync: resyncState,
      output: outcome === null ? '' : outcome.output.slice(-4000),
      message: '本地包升级失败，package.json 与 pnpm-lock.yaml 已回滚',
    }
  }

  cache.clear()
  let swap = { ok: false, reason: 'no idle moment to swap code' }
  try {
    const releaseSwap = await holdAgents(ctx)
    try {
      swap = await hotSwapUpdated(ctx)
    } finally {
      releaseSwap()
    }
  } catch {
    // Keep the result above; the caller reports it as restart-required.
  }
  writeUpdateLog(
    `OK ${name}`,
    `action: file-upgrade\n${plan.current} -> ${plan.target.version}\nasset: ${plan.target.asset.name} (${bytes} bytes)\nsha256: ${plan.target.sha256}\nhot swap: ${swap.ok === true ? 'ok' : swap.reason}\nidle gate: ${unguarded ? 'unavailable' : 'held'}`,
  )
  return markUnguarded(
    {
      ok: true,
      action: 'file-upgrade',
      name,
      from: plan.current,
      to: plan.target.version,
      asset: plan.target.asset.name,
      bytes,
      sha256: plan.target.sha256,
      output: outcome.output.slice(-800),
      hotSwap: swap,
      restart: swap.ok !== true,
    },
    unguarded,
  )
}

async function applyExtras(ctx, name, action) {
  const facts = profileFacts(ctx)
  if (facts === null) return { ok: false, message: 'profile package.json is unavailable' }
  const script = pnpmScript()
  if (script === null) return { ok: false, message: 'pnpm was not found next to the host' }
  const spec = typeof facts.deps[name] === 'string' ? facts.deps[name].trim() : ''
  if (spec === '') return { ok: false, message: 'unknown package' }

  if (action === 'repull') {
    if (!spec.startsWith('github:')) return { ok: false, message: '不是 GitHub 直装的包' }
    const match = GITHUB_SPEC.exec(spec)
    if (match === null) return { ok: false, message: '无法解析 github 地址' }
    let head
    try {
      head = await githubHead(match[1], match[2])
    } catch (error) {
      return { ok: false, message: error instanceof Error ? error.message : String(error) }
    }
    if (head.sha === null || head.sha === '') return { ok: false, message: 'github returned no commit hash' }
    // Pin to the head commit at action time. Re-adding the same floating spec
    // lets pnpm treat the lockfile as already satisfied and silently reuse the
    // old pin, which would make 重新拉取 a no-op.
    const result = await guardedPnpm(ctx, facts, script, [
      'add',
      `github:${match[1]}/${match[2]}#${head.sha}`,
      '--save-exact',
    ])
    return { ...result, restart: result.hotSwap?.ok !== true, action: 'repull', head }
  }
  if (action === 'pin') {
    if (!REMOTE_SPEC.test(spec)) return { ok: false, message: '不是压缩包安装的包' }
    let latest
    try {
      latest = await npmLatest(name, await configuredRegistry(ctx))
    } catch (error) {
      return { ok: false, message: error instanceof Error ? error.message : String(error) }
    }
    // Guard against downgrades: the npm latest can be OLDER than what the
    // tarball installed (dsh-our-free-model runs 2.8.0 while npm says 2.1.0).
    const current = installedVersion(facts.dir, name)
    if (current !== null && compareVersions(latest, current) <= 0) {
      return { ok: false, message: `npm 最新版本 ${latest} 不高于已安装的 ${current}，已取消（防止降级）` }
    }
    const result = await guardedPnpm(ctx, facts, script, ['add', `${name}@${latest}`, '--save-exact'])
    return { ...result, restart: result.hotSwap?.ok !== true, action: 'pin', latest }
  }
  if (action === 'file-upgrade') return applyFileUpgrade(ctx, name)
  return { ok: false, message: 'unknown action' }
}

/**
 * The registry this profile actually resolves packages from. pnpm's own answer
 * wins because it reflects the profile's configuration, so a mirror keeps
 * working and nothing here has to know what a mirror is.
 */
async function configuredRegistry(ctx) {
  try {
    const info = await ctx.pluginManager.registries()
    if (info === null || typeof info !== 'object') return null
    if (typeof info.resolved === 'string' && info.resolved.length > 0) return info.resolved
    const fallbacks = Array.isArray(info.fallbackRegistries) ? info.fallbackRegistries : []
    if (fallbacks.length > 0 && typeof fallbacks[0] === 'string') return fallbacks[0]
    return typeof info.registry === 'string' && info.registry.length > 0 ? info.registry : null
  } catch {
    return null
  }
}

/** The host's bundle record for a package, or null when nothing mounts it. */
async function bundleFor(ctx, name) {
  const all = await ctx.pluginManager.listBundles()
  return all.find((item) => item.name === name) ?? null
}

/** Every dependency the panel may remove: mounted here, and the host allows it. */
async function listRemovable(ctx) {
  const all = await ctx.pluginManager.listBundles()
  return all
    .filter((item) => item.removable === true && item.availability === 'profile' && !SELF_NAMES.includes(item.name))
    .map((item) => ({ name: item.name, version: item.version ?? null, enabled: item.enabled === true, installed: item.installed === true }))
}

/**
 * Uninstall a plugin through the host's own service. `removeBundle` owns the
 * profile write lock, unregisters the bundle, runs the package manager and
 * reloads in one transaction, and it refuses anything the host does not
 * consider removable — which is what keeps core packages safe. The manifest and
 * lockfile are copied first and restored when the removal throws.
 */
async function actUninstall(ctx, name) {
  if (typeof name !== 'string' || name.trim().length === 0) throw new HttpError(400, 'name is required')
  const target = name.trim()
  if (SELF_NAMES.includes(target)) throw new Error('不能卸载正在运行的面板本身，请用宿主自带的插件管理器')
  const bundle = await bundleFor(ctx, target)
  if (bundle === null) throw new Error(`${target} 不是本 profile 挂载的 bundle，无法卸载`)
  if (bundle.removable !== true) throw new Error(`${target} 由宿主管理，不允许卸载`)
  const facts = profileFacts(ctx)
  const backup = new Map()
  if (facts !== null) {
    for (const full of [facts.file, join(facts.dir, 'pnpm-lock.yaml')]) {
      try {
        backup.set(full, readFileSync(full, 'utf8'))
      } catch {
        // A missing lockfile is not a reason to refuse the removal.
      }
    }
  }
  try {
    const result = await ctx.pluginManager.removeBundle(target)
    cache.clear()
    return {
      ok: true,
      name: target,
      application: result === null || result === undefined ? null : (result.application ?? null),
      output: String(result?.packageResult?.output ?? '').slice(-4000),
    }
  } catch (error) {
    for (const [file, text] of backup) {
      try {
        writeFileSync(file, text, 'utf8')
      } catch {
        // Nothing better to do than report the original failure.
      }
    }
    throw error
  }
}

/**
 * Install a new bundle from a spec the host understands: an npm name, a
 * name@version, a directory, a git URL or a tarball URL. The spec is inspected
 * first, so a typo or a package that ships no bundle patch is refused before
 * anything is downloaded, and the install then goes through the host service —
 * which is what applies the compatibility check and the build-script policy
 * that a bare package manager call would skip.
 */
async function actInstall(ctx, spec) {
  if (typeof spec !== 'string' || spec.trim().length === 0) throw new HttpError(400, 'spec is required')
  const wanted = spec.trim()
  const inspection = await ctx.pluginManager.inspect(wanted)
  if (inspection === null || typeof inspection !== 'object' || inspection.status !== 'accepted') {
    return {
      ok: false,
      stage: 'inspect',
      problem: inspection?.problem ?? 'unknown',
      message: inspection?.reason ?? '宿主拒绝了这个来源',
    }
  }
  const result = await ctx.pluginManager.installBundle(wanted, { enabled: true, saveExact: true })
  cache.clear()
  const pending = Array.isArray(result?.pendingBuilds) ? result.pendingBuilds : []
  if (pending.length > 0) {
    return { ok: false, stage: 'build-approval', pendingBuilds: pending, message: '这些包需要在运行构建脚本前得到批准' }
  }
  const swap = await hotSwapUpdated(ctx)
  // 冲突对账：装完后看 loader 里有没有出现重复 entry id 或 moduleName。
  // 新装的那个先禁用，把决定权留给用户，别让两个同名插件抢着挂载同一个 API。
  const conflicts = []
  let rowsAfter = null
  try {
    rowsAfter = await readRows(ctx)
    const seenByEntryId = new Map()
    const seenByModule = new Map()
    for (const row of rowsAfter) {
      const byId = seenByEntryId.get(row.entryId)
      if (byId !== undefined) {
        conflicts.push({ kind: 'entryId', key: row.entryId, rows: [byId.name, row.name] })
      } else {
        seenByEntryId.set(row.entryId, row)
      }
      if (row.moduleName !== '') {
        const byModule = seenByModule.get(row.moduleName)
        if (byModule !== undefined) {
          conflicts.push({ kind: 'moduleName', key: row.moduleName, rows: [byModule.name, row.name] })
        } else {
          seenByModule.set(row.moduleName, row)
        }
      }
    }
    // 自动禁用新装那个名字对应的行（只要能定位到）。
    if (conflicts.length > 0 && typeof inspection.name === 'string') {
      // inspection.name 是包名（patchId 概念），要转换成具体的 entryId 才能用 setPluginEnabled。
      const mine = rowsAfter.filter(row => row.name === inspection.name || row.patchId === inspection.name)
      for (const row of mine) {
        try {
          await ctx.pluginManager.setPluginEnabled(row.entryId, false)
          conflicts.forEach(conflict => {
            if (conflict.autoDisabled === undefined) conflict.autoDisabled = []
            conflict.autoDisabled.push(row.entryId)
          })
        } catch {
          // 禁用失败就把冲突留给用户看，不装作处理好了。
        }
      }
    }
  } catch {
    // readRows 失败不该让安装本身失败；冲突只是没检测，不是装坏了。
  }
  return {
    ok: true,
    installed: {
      name: typeof inspection.name === 'string' ? inspection.name : null,
      version: typeof inspection.version === 'string' ? inspection.version : null,
      kind: typeof inspection.kind === 'string' ? inspection.kind : null,
      description: typeof inspection.description === 'string' ? inspection.description : null,
    },
    application: result === null || result === undefined ? null : (result.application ?? null),
    hotSwap: swap,
    restart: swap.ok !== true,
    output: String(result?.packageResult?.output ?? result?.output ?? '').slice(-4000),
    conflicts: conflicts.length > 0 ? conflicts : undefined,
  }
}

/** How often the idle watcher looks for queued work. */
const QUEUE_TICK_MS = 10 * 1000

/**
 * Apply one queued update as soon as every Agent is between turns.
 *
 * The host refuses a file swap while a turn is running — exactly what
 * `holdAgents` prevents — so a queued entry is only taken when the agents can be
 * claimed for the length of one pnpm run. Nothing here downloads: a queued
 * file-upgrade already has its verified tarball on disk, and a queued npm update
 * re-resolves with pnpm.
 */
async function pumpQueue(ctx) {
  const list = readQueue()
  if (list.length === 0) return
  if (activeJob !== null) return
  if (!beginMutation()) return
  const item = list[0]
  try {
    let release = null
    try {
      release = await holdAgents(ctx)
    } catch {
      return
    }
    release()
    const busy = result => result !== null && typeof result === 'object' && result.queued === true
    const failed = result => result === null || typeof result !== 'object' || result.ok !== true
    if (item.kind === 'updates') {
      const job = beginJob('updates', Array.isArray(item.names) ? item.names : [])
      const result = await applyUpdates(
        ctx,
        Array.isArray(item.names) ? item.names : [],
        Array.isArray(item.targets) ? item.targets : null,
        job,
      )
      endJob(job, result)
      if (busy(result)) return
      if (failed(result)) {
        dequeueItem(item)
        return
      }
    } else {
      const job = beginJob('extras', [item.name])
      const result = await applyExtras(ctx, item.name, typeof item.action === 'string' ? item.action : 'file-upgrade')
      endJob(job, result)
      if (busy(result)) return
      if (failed(result)) {
        dequeueItem(item)
        return
      }
    }
    dequeueItem(item)
  } catch (error) {
    void error
  } finally {
    endMutation()
  }
}

/**
 * The name part of a Host header. `[::1]:18338` has to come out as `::1`,
 * and a bare IPv6 literal has no port to strip, only brackets.
 */
/**
 * Whether a request's Origin may drive this API.
 *
 * The panel runs in the desktop shell, whose renderer is served from
 * `dsh-app://app` — not from a loopback URL — so comparing only against
 * 127.0.0.1 rejected every request the real panel made, and the page looked like
 * it was still loading (the fetch failed, nothing rendered). The hosted web
 * build does use a loopback origin, so both spellings have to pass.
 *
 * What this still refuses is the thing it was written for: any origin that is
 * not this app. A `file://` page, a random website and the `null` origin of a
 * sandboxed frame all fall through to false.
 */
function originAllowed(origin) {
  let parsed
  try {
    parsed = new URL(origin)
  } catch {
    return false
  }
  const host = parsed.hostname.toLowerCase()
  if (host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '[::1]') return true
  // The desktop shell's own scheme. `new URL('dsh-app://app')` gives
  // hostname 'app', so the protocol is what identifies it.
  if (parsed.protocol === 'dsh-app:') return true
  return false
}

function hostName(raw) {
  const text = String(raw ?? '').trim().toLowerCase()
  if (text === '') return ''
  if (text.startsWith('[')) {
    const end = text.indexOf(']')
    return end === -1 ? text : text.slice(1, end)
  }
  const colon = text.lastIndexOf(':')
  if (colon !== -1 && text.indexOf(':') === colon) return text.slice(0, colon)
  return text
}

async function handle(ctx, req, res) {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const path = url.pathname.slice(ROUTE_PREFIX.length) || '/'
  const method = req.method ?? 'GET'

  // 只接受来自 web GUI 本身的调用。两层防线：
  // 1. Host 必须是 127.0.0.1 / localhost / ::1 —— 拒绝 DNS rebinding（恶意域名解析到 127.0.0.1）。
  // 2. 有 Origin 就必须同源 —— 拒绝跨站 fetch。没 Origin 的是 curl / 同源导航，放过。
  const host = hostName(req.headers.host)
  const hostOk = host === '127.0.0.1' || host === 'localhost' || host === '::1'
  if (!hostOk) {
    return send(res, 403, { ok: false, message: 'host not allowed' })
  }
  const origin = req.headers.origin
  if (typeof origin === 'string' && origin !== '') {
    if (!originAllowed(origin)) {
      return send(res, 403, { ok: false, message: 'origin not allowed' })
    }
  }

  // Only JSON bodies are accepted, which also means a plain cross-origin form
  // post cannot reach an operation.
  if (method === 'POST') {
    const type = String(req.headers['content-type'] ?? '').toLowerCase()
    if (!type.startsWith('application/json')) {
      return send(res, 415, { ok: false, message: 'content-type must be application/json' })
    }
    // 写操作额外要求「你确实是从这个面板来的」。
    //
    // 前面两道闸（Host + Origin）只证明请求没被别的站点冒名，但对一个完全不带
    // Origin 的请求是放行的 —— `curl -X POST` 正好属于这类。这道门补上的是
    // 「声明意图」：挡住别处页面顺手打过来的盲发 POST、以及被 XSS 后的自动请求。
    //
    // 它**不是鉴权**。本机任何拿到这个端口的脚本，加一行请求头就能过；要真防住
    // 同机脚本，得引入 token/随机口令，目前没做。README 的「安全模型」章节说的
    // 是同一件事，两处不要各说各的。
    //
    // 判据：浏览器发的同源请求一定带 Origin 或 Sec-Fetch-Site；两者都没有的
    // 客户端必须显式带 `x-dsh-plugin-rack: 1`。
    const secFetchSite = String(req.headers['sec-fetch-site'] ?? '').toLowerCase()
    const explicit = String(req.headers['x-dsh-plugin-rack'] ?? '') === '1'
    const fromPage = origin !== undefined && origin !== null && String(origin) !== ''
    const sameSite = secFetchSite === 'same-origin' || secFetchSite === 'none'
    if (!fromPage && !sameSite && !explicit) {
      return send(res, 403, {
        ok: false,
        message:
          'write requests need an Origin header, same-site Sec-Fetch-Site, or an explicit x-dsh-plugin-rack: 1 header',
      })
    }
  }

  if (method === 'GET' && (path === '/ping' || path === '/')) {
    return send(res, 200, {
      ok: true,
      version: VERSION,
      statePath: stateFile(),
      // Which interpreter would run pnpm; a console node keeps it windowless.
      pnpmNode: nodeRuntime(),
      pnpmScript: pnpmScript(),
    })
  }
  if (method === 'GET' && path === '/state') {
    return send(res, 200, await snapshot(ctx))
  }
  // 技能：本插件自己扫描、自己存开关。不依赖任何别的插件。
  if (method === 'GET' && path === '/skills') {
    return send(res, 200, await skillSnapshot(ctx))
  }
  if (method === 'POST' && path === '/skills/toggle') {
    const body = await readJsonBody(req)
    const name = body !== null && typeof body === 'object' ? body.name : null
    const enabled = body !== null && typeof body === 'object' ? body.enabled : null
    if (typeof enabled !== 'boolean') {
      return send(res, 400, { ok: false, message: 'enabled must be a boolean' })
    }
    const result = setSkillEnabled(ctx, name, enabled)
    return send(res, 200, { ...result, ...(await skillSnapshot(ctx)) })
  }
  if (method === 'POST' && path === '/skills/note') {
    const body = await readJsonBody(req)
    const name = body !== null && typeof body === 'object' ? body.name : null
    const note = body !== null && typeof body === 'object' ? body.note : ''
    const result = setSkillNote(ctx, name, note)
    return send(res, 200, { ...result, ...(await skillSnapshot(ctx)) })
  }
  // 上一次/正在跑的更新任务。面板可能在中途被关掉，回来时靠这个续上进度。
  if (method === 'GET' && path === '/job') {
    return send(res, 200, { ok: true, job: jobStatus(), queue: readQueue() })
  }
  // 取消正在跑的那一次。下载阶段能立刻停，pnpm 阶段只能等它退出。
  if (method === 'POST' && path === '/job') {
    const body = await readJsonBody(req)
    const action = body !== null && typeof body === 'object' ? body.action : null
    if (action !== 'cancel') return send(res, 400, { ok: false, message: "action must be 'cancel'" })
    const result = cancelJob()
    return send(res, result.ok === true ? 200 : 409, result)
  }
  // 给脚本/未来的 agent 工具用的精简快照：每行只保留名字、版本、开关、phase、
  // 是否自动、是否核心。比 /state 干净，不带详情缓存、不带 bulk 进度。
  if (method === 'GET' && path === '/summary') {
    const rows = await readRows(ctx)
    const state = roster()
    const auto = new Set(state.auto)
    return send(res, 200, {
      ok: true,

      rows: rows.map(row => ({
        name: row.name,
        version: row.version,
        enabled: row.enabled,
        phase: row.phase,
        official: row.official,
        manageable: row.manageable,
        auto: auto.has(row.patchId),
        description: row.description,
      })),
    })
  }
  if (method === 'GET' && path === '/detail') {
    const entryId = url.searchParams.get('entryId') ?? ''
    if (entryId.length === 0) throw new HttpError(400, 'entryId is required')
    return send(res, 200, { ok: true, ...(await detailFor(ctx, entryId)) })
  }
  if (method === 'GET' && path === '/updates') {
    return send(res, 200, await checkUpdates(ctx))
  }
  if (method === 'POST' && path === '/updates') {
    // 更新同样要动 package.json + pnpm-lock.yaml，必须和其它写操作互斥。
    if (!beginMutation()) {
      return send(res, 200, { ok: false, message: BUSY_MESSAGE })
    }
    try {
      const body = await readJsonBody(req)
      const names = Array.isArray(body.names) ? body.names : []
      // 任务先在宿主登记再开跑：请求断了（面板关了、标签页没了）它照样跑完，
      // 结果写进 job.json，下次打开面板时由 /job 接回来。
      const job = beginJob('updates', names)
      try {
        const result = await applyUpdates(ctx, names, null, job)
        endJob(job, result)
        return send(res, 200, Object.assign({}, result, { jobId: job.id }))
      } catch (error) {
        endJob(job, { ok: false, message: error instanceof Error ? error.message : String(error) })
        throw error
      }
    } finally {
      endMutation()
    }
  }
  if (method === 'GET' && path === '/updatelog') {
    const file = join(stateDir(), 'last-update.log')
    try {
      const text = readFileSync(file, 'utf8')
      send(res, 200, { ok: true, path: file, text })
    } catch {
      send(res, 200, { ok: true, path: file, text: null })
    }
    return
  }

  if (method === 'GET' && path === '/extras') {
    return send(res, 200, await listExtras(ctx))
  }
  if (method === 'POST' && path === '/extras') {
    // 「重新拉取 / 改为按版本安装」也会跑 pnpm，同样进互斥区。
    if (!beginMutation()) {
      return send(res, 200, { ok: false, message: BUSY_MESSAGE })
    }
    try {
      const body = await readJsonBody(req)
      const action = String(body.action ?? '')
      const job = beginJob('extras', [String(body.name ?? '')])
      try {
        const result = await applyExtras(ctx, String(body.name ?? ''), action)
        endJob(job, result)
        return send(res, 200, Object.assign({}, result, { jobId: job.id }))
      } catch (error) {
        endJob(job, { ok: false, message: error instanceof Error ? error.message : String(error) })
        throw error
      }
    } finally {
      endMutation()
    }
  }
  if (method === 'GET' && path === '/registries') {
    const info = await ctx.pluginManager.registries()
    return send(res, 200, { ok: true, ...(info ?? {}), github: typeof process.env.GITHUB_TOKEN === 'string' && process.env.GITHUB_TOKEN.trim().length > 0 })
  }
  if (method === 'GET' && path === '/inspect') {
    // 只做预检，不装任何东西：把宿主 inspect 的结果原样交给界面，
    // 这样「安装」按钮点下去之前，用户已经能看到要装的到底是哪个包、什么版本。
    const spec = (url.searchParams.get('spec') ?? '').trim()
    if (spec === '') return send(res, 400, { ok: false, message: 'spec is required' })
    try {
      return send(res, 200, { ok: true, inspection: await ctx.pluginManager.inspect(spec) })
    } catch (error) {
      return send(res, 200, { ok: false, message: error instanceof Error ? error.message : String(error) })
    }
  }
  if (method === 'GET' && path === '/fileplan') {
    // 本地 file: 包的升级预览：只读，不下载、不改任何文件。
    const name = (url.searchParams.get('name') ?? '').trim()
    if (name === '') return send(res, 400, { ok: false, message: 'name is required' })
    try {
      return send(res, 200, await planFileUpgrade(ctx, name))
    } catch (error) {
      return send(res, 200, { ok: false, message: error instanceof Error ? error.message : String(error) })
    }
  }
  if (method === 'GET' && path === '/removable') {
    return send(res, 200, { ok: true, rows: await listRemovable(ctx) })
  }
  if (method === 'POST' && path === '/install') {
    if (!beginMutation()) {
      return send(res, 200, { ok: false, message: BUSY_MESSAGE })
    }
    try {
      const body = await readJsonBody(req)
      return send(res, 200, await actInstall(ctx, body.spec))
    } finally {
      endMutation()
    }
  }
  if (method === 'POST' && path === '/uninstall') {
    if (!beginMutation()) {
      return send(res, 200, { ok: false, message: BUSY_MESSAGE })
    }
    try {
      const body = await readJsonBody(req)
      return send(res, 200, await actUninstall(ctx, body.name))
    } finally {
      endMutation()
    }
  }
  if (method === 'POST' && path === '/plugin') {
    if (!beginMutation()) {
      return send(res, 200, { ok: false, message: BUSY_MESSAGE })
    }
    try {
      return send(res, 200, await actPlugin(ctx, await readJsonBody(req)))
    } finally {
      endMutation()
    }
  }
  if (method === 'POST' && path === '/bundle') {
    if (!beginMutation()) {
      return send(res, 200, { ok: false, message: BUSY_MESSAGE })
    }
    try {
      const body = await readJsonBody(req)
      const name = typeof body.name === 'string' ? body.name.trim() : ''
      if (name === '') throw new HttpError(400, 'name is required')
      if (SELF_NAMES.includes(name)) {
        throw new HttpError(400, 'the dashboard refuses to switch itself off')
      }
      if (typeof body.enabled !== 'boolean') throw new HttpError(400, 'enabled must be a boolean')
      const manager = ctx.pluginManager
      if (manager === null || manager === undefined || typeof manager.setBundleEnabled !== 'function') {
        throw new HttpError(500, 'this host cannot switch a bundle layer')
      }
      // 先把文件写对，再交给宿主决定是热挂载还是要求重启。
      const result = await manager.setBundleEnabled(name, body.enabled)
      cache.clear()
      return send(res, 200, { ok: true, name, enabled: body.enabled, result })
    } finally {
      endMutation()
    }
  }
  if (method === 'POST' && path === '/bulk') {
    const body = await readJsonBody(req)
    if (body.cancel === true) return send(res, 200, cancelBulk())
    if (typeof body.enabled !== 'boolean') throw new HttpError(400, 'enabled must be a boolean')
    const mode = body.save === true ? 'save' : 'live'
    return send(res, 200, await actBulk(ctx, body.enabled, String(body.scope ?? ''), mode))
  }
  if (method === 'POST' && path === '/roster') {
    const body = await readJsonBody(req)
    return send(
      res,
      200,
      await actRoster(
        ctx,
        String(body.mode ?? ''),
        body.mode === 'names' && Array.isArray(body.names) ? body.names : String(body.scope ?? ''),
        body.auto === true,
      ),
    )
  }
  const allowed = ROUTES[path]
  if (allowed !== undefined) {
    res.setHeader('allow', allowed.join(', '))
    return send(res, 405, { ok: false, message: `method ${method} is not allowed on ${path}` })
  }
  return send(res, 404, { ok: false, message: `unknown route ${method} ${path}` })
}

export function apply(ctx) {
  adoptProfile(ctx)
  // 把自己的技能开关接进核心的 skills 服务：只对「已停用」的技能投一张
  // 低优先级的不可调用候选，让核心把它们从模型上下文里滤掉。启用的技能
  // 一张都不投，照旧由官方 provider 加载——这里解析出错也伤不到正常技能。
  ctx.effect(() => {
    const skills = typeof ctx.get === 'function' ? ctx.get('skills') : undefined
    if (skills === undefined || typeof skills.registerProvider !== 'function') return () => {}
    const provider = createSkillPolicyProvider({
      read: () => readSkillState(stateDir()),
      scan: async () =>
        resolveWinners(
          scanSkills(
            skillRoots({
              projectRoots: projectRootsOf(ctx),
              pluginRoots: pluginSkillPackages(await nodeModulesRootOf(ctx)),
            }),
          ).skills,
        ),
    })
    return skills.registerProvider(() => provider)
  }, 'rack skill policy provider')
  ctx.effect(() =>
    ctx.webServer.register({
      kind: 'prefix',
      path: ROUTE_PREFIX,
      handler: (req, res) =>
        handle(ctx, req, res).catch(error => {
          const message = error instanceof Error ? error.message : String(error)
          const status = error instanceof HttpError ? error.status : 500
          if (!res.headersSent) send(res, status, { ok: false, message })
          else if (!res.writableEnded && !res.destroyed) res.end()
          else void 0
        }),
    }),
  )

  // Queued updates must outlive the panel that asked for them: this timer is the
  // only thing that turns "downloaded, waiting for a free moment" into "installed".
  // It is unref'd so a test or a short-lived host never waits on the queue.
  ctx.effect(() => {
    const timer = setInterval(() => {
      pumpQueue(ctx).catch(() => {})
    }, QUEUE_TICK_MS)
    if (typeof timer.unref === 'function') timer.unref()
    return () => clearInterval(timer)
  })
}
