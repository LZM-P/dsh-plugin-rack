/**
 * The rack's own skill management.
 *
 * Everything here is written against the DSH core `skills` service contract
 * (registerProvider / list / get), not against another plugin's private API:
 *
 *   - Scanning: this module walks the skill roots itself and parses
 *     `SKILL.md` frontmatter with a small YAML subset reader. It only reads
 *     the roots DSH itself loads (user `.dsh/skills`, shared `.agents/skills`,
 *     the active project's `.dsh/skills`, and a preset directory when given),
 *     never other agents' private folders.
 *
 *   - Switching: DSH has no per-skill enable flag to flip, so "off" is
 *     expressed the way the core already understands it — a candidate whose
 *     `invocation` says it may not be invoked by any consumer. This module
 *     registers one provider that contributes such a candidate ONLY for the
 *     skills the user switched off, and only with a lower rank than the
 *     shipped provider so it wins the merge for that one name. Enabled skills
 *     are not touched at all: the official provider keeps loading them, so a
 *     bug in this parser can never take a working skill away.
 *
 *   - Storage: the on/off list and per-skill notes live in the rack's own
 *     state file next to the plugin state, written atomically.
 */
import { mkdirSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/** Read an environment variable without depending on @types/node. */
function envValue(/** @type {string} */ name) {
  const holder = /** @type {{ process?: { env?: Record<string, string | undefined> } }} */ (globalThis)
  const value = holder.process?.env?.[name]
  return typeof value === 'string' ? value.trim() : ''
}

/** Skill names follow the public grammar: kebab-case or a single word. */
const SKILL_NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
/** Lower rank wins inside one layer. 50 beats every shipped root (100+). */
const POLICY_RANK = 50
const PROVIDER_NAME = 'rack-skill-policy'
/** Scanner limits, so one pathological folder cannot hang the panel. */
const MAX_ENTRIES = 2000
const MAX_FILE_BYTES = 256 * 1024

/**
 * One skill as this module understands it: the file it came from, whether it
 * could be read, and the invocation policy the frontmatter declares.
 *
 * @typedef {object} SkillEntry
 * @property {string} name
 * @property {string} dir
 * @property {string} path
 * @property {string} [rootKey]
 * @property {string} [rootLabel]
 * @property {string} [scope]
 * @property {number} [rank]
 * @property {boolean} loadable
 * @property {string} [problem]
 * @property {string} [description]
 * @property {string} [whenToUse]
 * @property {number} [bodyBytes]
 * @property {boolean} [linked]
 * @property {boolean} [modelInvocable]
 * @property {boolean} [userInvocable]
 * @property {boolean} [winner]
 * @property {{ rootKey: string, path: string }} [shadowedBy]
 * @property {boolean} [enabled]
 * @property {string} [customNote]
 * @property {boolean} [effectiveModelInvocable]
 * @property {boolean} [effectiveUserInvocable]
 */

/**
 * Resolve the directories DSH loads skills from, in precedence order.
 * Mirrors the shipped filesystem provider's default roots without importing it.
 *
 * Roots come in two kinds. The first four are directories the shipped provider
 * reads directly. The last one is different: plugins ship their own `skills/`
 * directory inside the package, and the provider loads those too, but they are
 * not a single directory to walk — one root per installed bundle, discovered
 * from `node_modules`. A panel that only listed the first kind showed 342
 * skills on a machine that actually loads 360.
 *
 * @param {{ dshHome?: string, agentsHome?: string, projectRoots?: string[], pluginRoots?: string[] }} options
 * @returns {Array<{ key: string, label: string, path: string, rank: number, scope: string }>}
 */
export function skillRoots(options = {}) {
  const dshHome =
    typeof options.dshHome === 'string' && options.dshHome !== ''
      ? options.dshHome
      : envValue('DSH_HOME') !== ''
        ? envValue('DSH_HOME')
        : join(homedir(), '.dsh')
  const agentsHome =
    typeof options.agentsHome === 'string' && options.agentsHome !== ''
      ? options.agentsHome
      : envValue('DSH_AGENTS_HOME') !== ''
        ? envValue('DSH_AGENTS_HOME')
        : join(homedir(), '.agents')
  const roots = []
  for (const projectRoot of options.projectRoots ?? []) {
    if (typeof projectRoot !== 'string' || projectRoot === '') continue
    roots.push({
      key: 'project:' + projectRoot,
      label: 'project',
      path: join(projectRoot, '.dsh', 'skills'),
      rank: 100,
      scope: 'project',
    })
    roots.push({
      key: 'project-agents:' + projectRoot,
      label: 'project',
      path: join(projectRoot, '.agents', 'skills'),
      rank: 200,
      scope: 'project',
    })
  }
  roots.push({ key: 'user', label: 'user', path: join(dshHome, 'skills'), rank: 400, scope: 'user' })
  roots.push({ key: 'agents', label: 'shared', path: join(agentsHome, 'skills'), rank: 500, scope: 'user' })
  // Plugin-bundled skills rank last: a user or project copy of the same name
  // should win over whatever a package happens to ship.
  for (const bundle of options.pluginRoots ?? []) {
    if (typeof bundle !== 'string' || bundle === '') continue
    roots.push({
      key: 'plugin:' + bundle,
      label: 'plugins',
      path: join(bundle, 'skills'),
      rank: 600,
      scope: 'plugin',
    })
  }
  return roots
}

/**
 * Every installed package that ships a `skills/` directory.
 *
 * Reads one level of `node_modules`, plus one more inside each `@scope`
 * directory, and keeps every package that has a `skills` subdirectory.
 * Deliberately not recursive: a package that nests skills under its own build
 * output is not something the provider loads either.
 *
 * @param {string|null} nodeModulesRoot  absolute path to a profile's node_modules
 * @returns {string[]} absolute package directories, sorted
 */
export function pluginSkillPackages(nodeModulesRoot) {
  if (typeof nodeModulesRoot !== 'string' || nodeModulesRoot === '') return []
  /** @type {string[]} */
  const found = []
  /** @param {string} dir */
  const hasSkills = (dir) => {
    try {
      return statSync(join(dir, 'skills')).isDirectory()
    } catch {
      return false
    }
  }
  /** @type {import('node:fs').Dirent[]} */
  let names = []
  try {
    names = readdirSync(nodeModulesRoot, { withFileTypes: true })
  } catch {
    return []
  }
  for (const dirent of names) {
    if (!dirent.isDirectory() && !dirent.isSymbolicLink()) continue
    if (dirent.name.startsWith('.')) continue
    const full = join(nodeModulesRoot, dirent.name)
    if (dirent.name.startsWith('@')) {
      /** @type {import('node:fs').Dirent[]} */
      let scoped = []
      try {
        scoped = readdirSync(full, { withFileTypes: true })
      } catch {
        continue
      }
      for (const inner of scoped) {
        if (!inner.isDirectory() && !inner.isSymbolicLink()) continue
        const pkg = join(full, inner.name)
        if (hasSkills(pkg)) found.push(pkg)
      }
      continue
    }
    if (hasSkills(full)) found.push(full)
  }
  found.sort((left, right) => left.localeCompare(right))
  return found
}

/**
 * Read one skill's frontmatter. Deliberately a small reader for the keys the
 * contract needs; anything it cannot parse is reported, never guessed.
 *
 * @param {string} text
 * @returns {{ ok: true, name: string, description: string, whenToUse?: string, invocation: { modelInvocable: boolean, userInvocable: boolean }, body: string } | { ok: false, problem: string }}
 */
export function parseSkillDoc(text) {
  const source = String(text).replace(/^\uFEFF/, '')
  const open = source.indexOf('---')
  if (open !== 0) return { ok: false, problem: 'missing frontmatter' }
  const close = source.indexOf('\n---', 3)
  if (close < 0) return { ok: false, problem: 'unterminated frontmatter' }
  const head = source.slice(3, close)
  const body = source.slice(close + 4).replace(/^\r?\n/, '')
  /** @type {Record<string, string | boolean>} */
  const fields = {}
  for (const line of head.split(/\r?\n/)) {
    if (line.trim() === '' || line.trimStart().startsWith('#')) continue
    const match = /^([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*)$/.exec(line)
    if (match === null) continue
    const key = match[1]
    let value = match[2].trim()
    if (/^['"]/.test(value)) {
      value = value.replace(/^(['"])([\s\S]*)\1$/, '$2')
    } else if (value === 'true' || value === 'false') {
      fields[key] = value === 'true'
      continue
    }
    fields[key] = value
  }
  const name = typeof fields.name === 'string' ? fields.name.trim() : ''
  const description = typeof fields.description === 'string' ? fields.description.trim() : ''
  const whenToUse = typeof fields.whenToUse === 'string' ? fields.whenToUse.trim() : ''
  if (name === '' || !SKILL_NAME.test(name)) return { ok: false, problem: 'invalid name' }
  if (description === '') return { ok: false, problem: 'missing description' }
  const disableModel = fields['disable-model-invocation']
  const userInvocableField = fields['user-invocable']
  // These two frontmatter keys are the core's own spelling, so honouring them
  // keeps a skill authored that way behaving the same before and after.
  return {
    ok: true,
    name,
    description,
    ...(whenToUse === '' ? {} : { whenToUse }),
    invocation: {
      modelInvocable: disableModel !== true,
      userInvocable: userInvocableField !== false,
    },
    body,
  }
}

/**
 * Scan every root once. Never throws for a bad root: a missing or unreadable
 * directory is reported per root so the panel can say which one it was.
 *
 * @param {ReturnType<typeof skillRoots>} roots
 * @returns {{ skills: SkillEntry[], roots: Array<{ key: string, label: string, path: string, scope: string, rank: number, exists: boolean, skills: SkillEntry[] }> }}
 */
export function scanSkills(roots) {
  /** @type {Array<{ key: string, label: string, path: string, scope: string, rank: number, exists: boolean, skills: SkillEntry[] }>} */
  const rootsOut = []
  /** @type {SkillEntry[]} */
  const skills = []
  for (const root of roots) {
    /** @type {{ key: string, label: string, path: string, scope: string, rank: number, exists: boolean, skills: SkillEntry[] }} */
    const entry = {
      key: root.key,
      label: root.label,
      path: root.path,
      scope: root.scope,
      rank: root.rank,
      exists: false,
      skills: [],
    }
    /** @type {import('node:fs').Dirent[]} */
    let names = []
    try {
      entry.exists = statSync(root.path).isDirectory()
      if (entry.exists) names = readdirSync(root.path, { withFileTypes: true })
    } catch {
      entry.exists = false
    }
    if (!entry.exists) {
      rootsOut.push(entry)
      continue
    }
    let seen = 0
    /**
     * 一份数据、两处引用：分组列表给界面，平铺列表给策略层。分开各推一次
     * 就会出现「界面里有、开关却不认」的幽灵条目（自测抓到过）。
     *
     * @param {{ name: string, loadable: boolean, problem?: string, dir?: string, path?: string, description?: string, bodyBytes?: number, linked?: boolean, whenToUse?: string, modelInvocable?: boolean, userInvocable?: boolean }} skillDir
     */
    const record = (skillDir) => {
      /** @type {SkillEntry} */
      const full = {
        path: join(root.path, skillDir.dir || skillDir.name, 'SKILL.md'),
        dir: skillDir.dir || skillDir.name,
        ...skillDir,
        rootKey: root.key,
        rootLabel: root.label,
        // scope goes on the entry too: the panel groups by it and the tests
        // assert that a bundled skill is recognisably a plugin skill.
        scope: root.scope,
        rank: root.rank,
      }
      entry.skills.push(full)
      skills.push(full)
    }
    for (const dirent of names) {
      if (seen >= MAX_ENTRIES) break
      if (!dirent.isDirectory() && !dirent.isSymbolicLink()) continue
      seen += 1
      const file = join(root.path, dirent.name, 'SKILL.md')
      let text
      try {
        // 直接用 readFileSync 试读：它自己就会对不存在/不可读抛错，比先
        // existsSync 再 statSync 再读少两次系统调用——600 个技能时这就是
        // 一个数量级的差别。
        text = readFileSync(file, 'utf8')
      } catch (error) {
        // ENOENT 是「这个目录不是技能」，不是问题，别记进列表。
        if (error !== null && typeof error === 'object' && /** @type {{ code?: string }} */ (error).code === 'ENOENT') continue
        record({ name: dirent.name, loadable: false, problem: 'unreadable' })
        continue
      }
      if (text.length > MAX_FILE_BYTES) {
        record({ name: dirent.name, loadable: false, problem: 'file too large' })
        continue
      }
      const parsed = parseSkillDoc(text)
      if (parsed.ok !== true) {
        record({ name: dirent.name, loadable: false, problem: parsed.problem })
        continue
      }
      /** @type {SkillEntry} */
      const doc = {
        name: parsed.name,
        dir: dirent.name,
        path: file,
        loadable: true,
        description: parsed.description,
        bodyBytes: Buffer.byteLength(parsed.body, 'utf8'),
      }
      if (dirent.isSymbolicLink()) doc.linked = true
      if (parsed.whenToUse !== undefined) doc.whenToUse = parsed.whenToUse
      doc.modelInvocable = parsed.invocation.modelInvocable
      doc.userInvocable = parsed.invocation.userInvocable
      record({ ...doc, loadable: true })
    }
    rootsOut.push(entry)
  }
  return { skills, roots: rootsOut }
}

/**
 * Collapse same-named skills to the one that actually wins, and mark the rest.
 * The winner is the lowest rank (project beats user, DSH beats shared), which
 * is the same rule the core applies when merging providers.
 *
 * @param {SkillEntry[]} skills flat list from scanSkills
 * @returns {SkillEntry[]} each with `winner` and optional `shadowedBy`
 */
export function resolveWinners(skills) {
  const byName = new Map()
  for (const skill of skills) {
    if (skill.loadable !== true) continue
    const current = byName.get(skill.name)
    if (current === undefined || (skill.rank ?? Infinity) < (current.rank ?? Infinity)) byName.set(skill.name, skill)
  }
  return skills.map((skill) => {
    if (skill.loadable !== true) return skill
    const winner = byName.get(skill.name)
    if (winner === undefined || winner === skill) return { ...skill, winner: true }
    return { ...skill, winner: false, shadowedBy: { rootKey: winner.rootKey, path: winner.path } }
  })
}

/**
 * Where the rack keeps its own skill state. Deliberately separate from the
 * plugin roster file: this one is about skills, and mixing them would make a
 * corrupt skill list able to take the plugin dashboard down.
 *
 * @param {string} base directory (usually the plugin's own state dir)
 * @returns {string}
 */
export function skillStatePath(base) {
  return join(base, 'skills.json')
}

/**
 * @param {string} base
 * @returns {{ disabled: string[], notes: Record<string, string> }}
 */
export function readSkillState(base) {
  const empty = { disabled: [], notes: {} }
  try {
    const raw = readFileSync(skillStatePath(base), 'utf8')
    const parsed = JSON.parse(raw)
    if (parsed === null || typeof parsed !== 'object') return empty
    const disabled = Array.isArray(parsed.disabled)
      ? parsed.disabled.filter((/** @type {unknown} */ name) => typeof name === 'string' && name !== '')
      : []
    const notes =
      parsed.notes !== null && typeof parsed.notes === 'object' && !Array.isArray(parsed.notes)
        ? Object.fromEntries(
            Object.entries(parsed.notes).filter(
              (pair) => typeof pair[0] === 'string' && typeof pair[1] === 'string',
            ),
          )
        : {}
    return { disabled, notes }
  } catch {
    return empty
  }
}

/**
 * Write the state atomically: a half-written file would otherwise switch every
 * skill back on at the next start, which reads as data loss to the user.
 *
 * @param {string} base
 * @param {{ disabled: string[], notes: Record<string, string> }} value
 */
export function writeSkillState(base, value) {
  const target = skillStatePath(base)
  mkdirSync(base, { recursive: true })
  const temp = target + '.tmp-' + String(Date.now())
  writeFileSync(temp, JSON.stringify(value, null, 2) + '\n', 'utf8')
  renameSync(temp, target)
}

/**
 * Apply the on/off list to a scan, so the panel and the provider agree.
 *
 * @param {SkillEntry[]} skills resolved list
 * @param {{ disabled: string[], notes: Record<string, string> }} state
 * @returns {SkillEntry[]}
 */
export function applySkillState(skills, state) {
  const disabled = new Set(state.disabled)
  return skills.map((skill) => {
    const off = disabled.has(skill.name) && skill.loadable === true
    const next = {
      ...skill,
      enabled: skill.loadable === true && !off,
      customNote: state.notes[skill.name] ?? '',
    }
    if (off) {
      // A switched-off skill is still listed, but reports how the core will see
      // it: nobody may invoke it. That is the whole mechanism behind "off".
      next.effectiveModelInvocable = false
      next.effectiveUserInvocable = false
    } else {
      next.effectiveModelInvocable = skill.modelInvocable !== false
      next.effectiveUserInvocable = skill.userInvocable !== false
    }
    return next
  })
}

/**
 * Build the provider the core `skills` service will consult.
 *
 * It answers for EVERY name it knows (so a switched-off skill always wins the
 * merge and cannot fall back to the official copy), but it only marks a skill
 * as non-invocable when the user switched it off. Everything else is passed
 * through with the same invocation policy the file declares, and `get()`
 * returns undefined for those so the official provider still owns loading —
 * this module never becomes a second source of skill bodies.
 *
 * @param {{ read: () => { disabled: string[], notes: Record<string, string> }, scan: () => SkillEntry[] | Promise<SkillEntry[]> }} deps
 * @returns {{ name: string, list: Function, get: Function }}
 */
export function createSkillPolicyProvider(deps) {
  return {
    name: PROVIDER_NAME,
    async list() {
      const state = deps.read()
      const disabled = new Set(state.disabled)
      if (disabled.size === 0) return { candidates: [], complete: true }
      const skills = await deps.scan()
      const candidates = []
      const seen = new Set()
      for (const skill of skills) {
        if (skill.loadable !== true) continue
        if (!disabled.has(skill.name)) continue
        // 同名技能在多个根各有一份时只投一张：核心按名字合并，投两张等于
        // 让一个名字占两个位置，且其中一张必然是多余的影子副本。
        if (seen.has(skill.name)) continue
        seen.add(skill.name)
        candidates.push({
          name: skill.name,
          description: skill.description,
          ...(skill.whenToUse === undefined ? {} : { whenToUse: skill.whenToUse }),
          invocation: { modelInvocable: false, userInvocable: false },
          source: skill.path,
          rank: POLICY_RANK,
          provider: PROVIDER_NAME,
          path: skill.path,
        })
      }
      return { candidates, complete: true }
    },
    get() {
      // Never a body source: off skills are filtered out by the core before it
      // asks anyone to load them, and on skills belong to the shipped provider.
      return undefined
    },
  }
}

export { POLICY_RANK, PROVIDER_NAME, SKILL_NAME }
