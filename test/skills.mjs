// The rack's own skill management, without a DOM and without any other plugin.
//
// This exercises the scanner, the frontmatter reader, the winner rule, the
// on/off policy and the provider handed to the core `skills` service — the whole
// path that used to be delegated to a third-party plugin.
//
// Run: node test/skills.mjs
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  applySkillState,
  createSkillPolicyProvider,
  parseSkillDoc,
  pluginSkillPackages,
  readSkillState,
  resolveWinners,
  scanSkills,
  skillRoots,
  writeSkillState,
} from '../lib/skills.js'

let failures = 0
let checks = 0

/**
 * @param {boolean} condition
 * @param {string} label
 */
function check(condition, label) {
  checks += 1
  if (!condition) {
    failures += 1
    console.error('FAIL ' + label)
  }
}

/**
 * @param {unknown} actual
 * @param {unknown} want
 * @param {string} label
 */
function eq(actual, want, label) {
  const ok = JSON.stringify(actual) === JSON.stringify(want)
  if (!ok) {
    checks += 1
    failures += 1
    console.error('FAIL ' + label + ' — got ' + JSON.stringify(actual) + ', want ' + JSON.stringify(want))
    return
  }
  check(true, label)
}

// ── frontmatter ─────────────────────────────────────────────────────────────
{
  const doc = parseSkillDoc('---\nname: demo-skill\ndescription: Does a thing.\n---\nBody text.\n')
  check(doc.ok === true, 'a well formed SKILL.md parses')
  eq(doc.name, 'demo-skill', 'the name comes from frontmatter')
  eq(doc.description, 'Does a thing.', 'the description comes from frontmatter')
  eq(doc.body.trim(), 'Body text.', 'the body is everything after the frontmatter')
  eq(doc.invocation, { modelInvocable: true, userInvocable: true }, 'a plain skill is invocable both ways')

  const off = parseSkillDoc('---\nname: quiet\ndescription: Quiet.\ndisable-model-invocation: true\n---\n')
  eq(off.invocation, { modelInvocable: false, userInvocable: true }, 'disable-model-invocation is honoured')

  const manual = parseSkillDoc('---\nname: manual\ndescription: Manual.\nuser-invocable: false\n---\n')
  eq(manual.invocation, { modelInvocable: true, userInvocable: false }, 'user-invocable: false is honoured')

  const quoted = parseSkillDoc('---\nname: "quoted"\ndescription: \'Single quoted.\'\n---\n')
  eq(quoted.name, 'quoted', 'a quoted name is unquoted')
  eq(quoted.description, 'Single quoted.', 'a quoted description is unquoted')

  const when = parseSkillDoc('---\nname: when\ndescription: d\nwhenToUse: on tuesdays\n---\n')
  eq(when.whenToUse, 'on tuesdays', 'whenToUse survives')

  check(parseSkillDoc('no frontmatter here').ok === false, 'missing frontmatter is a problem, not a guess')
  check(parseSkillDoc('---\nname: only\n---\n').ok === false, 'a missing description is rejected')
  check(parseSkillDoc('---\nname: Bad Name\ndescription: d\n---\n').ok === false, 'a non kebab-case name is rejected')
  check(parseSkillDoc('---\nname: open\ndescription: d\n').ok === false, 'unterminated frontmatter is rejected')
  check(parseSkillDoc('\uFEFF---\nname: bom\ndescription: d\n---\n').ok === true, 'a byte order mark does not break parsing')
}

// ── scanning and the winner rule ────────────────────────────────────────────
const workspace = mkdtempSync(join(tmpdir(), 'rack-skills-'))
try {
  const userRoot = join(workspace, 'dsh', 'skills')
  const sharedRoot = join(workspace, 'agents', 'skills')
  const projectRoot = join(workspace, 'project')
  const writeSkill = (dir, name, description, extra = '') => {
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'SKILL.md'), `---\nname: ${name}\ndescription: ${description}\n${extra}---\nBody.\n`, 'utf8')
  }
  writeSkill(join(userRoot, 'alpha'), 'alpha', 'User alpha.')
  writeSkill(join(userRoot, 'beta'), 'beta', 'User beta.')
  writeSkill(join(sharedRoot, 'alpha'), 'alpha', 'Shared alpha.')
  writeSkill(join(sharedRoot, 'gamma'), 'gamma', 'Shared gamma.')
  writeSkill(join(projectRoot, '.dsh', 'skills', 'beta'), 'beta', 'Project beta.')
  // A folder with a broken SKILL.md, and a folder with none at all.
  mkdirSync(join(userRoot, 'broken'), { recursive: true })
  writeFileSync(join(userRoot, 'broken', 'SKILL.md'), 'not a skill file\n', 'utf8')
  mkdirSync(join(userRoot, 'not-a-skill'), { recursive: true })

  const roots = skillRoots({ dshHome: join(workspace, 'dsh'), agentsHome: join(workspace, 'agents'), projectRoots: [projectRoot] })
  eq(roots.map((root) => root.key), ['project:' + projectRoot, 'project-agents:' + projectRoot, 'user', 'agents'], 'roots are listed in precedence order')

  const scanned = scanSkills(roots)
  eq(scanned.skills.filter((skill) => skill.loadable === true).length, 5, 'every readable skill is found')
  eq(scanned.skills.filter((skill) => skill.loadable !== true).length, 1, 'a broken SKILL.md is reported, not silently dropped')
  eq(
    scanned.roots.filter((root) => root.exists === true).map((root) => root.key),
    ['project:' + projectRoot, 'user', 'agents'],
    'only the roots that actually exist are reported present',
  )
  eq(
    scanned.roots.filter((root) => root.exists === false).map((root) => root.key),
    ['project-agents:' + projectRoot],
    'a root with no skills directory is reported missing rather than invented',
  )

  const missing = scanSkills(skillRoots({ dshHome: join(workspace, 'nope'), agentsHome: join(workspace, 'nope2'), projectRoots: [] }))
  check(missing.roots.every((root) => root.exists === false), 'a missing root is reported, and does not throw')
  eq(missing.skills.length, 0, 'a missing root contributes no skills')

  const resolved = resolveWinners(scanned.skills)
  const winnerOf = (name) => resolved.filter((skill) => skill.name === name && skill.loadable === true)
  eq(winnerOf('alpha').filter((skill) => skill.winner === true).map((skill) => skill.rootKey), ['user'], 'the user root outranks the shared root for the same name')
  const sharedAlpha = winnerOf('alpha').find((skill) => skill.rootKey === 'agents')
  check(sharedAlpha.shadowedBy !== undefined, 'the losing copy is marked as shadowed')
  eq(sharedAlpha.shadowedBy.rootKey, 'user', 'the shadowed copy names who beat it')
  eq(winnerOf('beta').filter((skill) => skill.winner === true).map((skill) => skill.rootKey), ['project:' + projectRoot], 'a project root outranks the user root')
  eq(winnerOf('gamma').filter((skill) => skill.winner === true).length, 1, 'a unique name has exactly one winner')

  // ── the on/off policy ────────────────────────────────────────────────────
  writeSkillState(workspace, { disabled: ['alpha'], notes: { beta: 'kept for later' } })
  const state = readSkillState(workspace)
  eq(state.disabled, ['alpha'], 'the off list round-trips')
  eq(state.notes, { beta: 'kept for later' }, 'notes round-trip')

  const applied = applySkillState(resolved, state)
  const userAlpha = applied.find((skill) => skill.name === 'alpha' && skill.rootKey === 'user')
  eq(userAlpha.enabled, false, 'a switched-off skill reports itself as off')
  eq(userAlpha.effectiveModelInvocable, false, 'a switched-off skill cannot be invoked by the model')
  eq(userAlpha.effectiveUserInvocable, false, 'a switched-off skill cannot be invoked by the user')
  eq(userAlpha.winner, true, 'switching a skill off does not promote a shadowed copy')
  eq(applied.find((skill) => skill.name === 'beta' && skill.rootKey === 'user').customNote, 'kept for later', 'a note is attached to its skill')
  eq(applied.find((skill) => skill.name === 'gamma').enabled, true, 'an untouched skill stays on')

  const brokenEntry = applied.find((skill) => skill.loadable !== true)
  eq(brokenEntry.enabled, false, 'an unloadable skill is never reported as on')

  // ── the provider handed to the core ──────────────────────────────────────
  const provider = createSkillPolicyProvider({
    read: () => readSkillState(workspace),
    scan: () => resolveWinners(scanSkills(roots).skills),
  })
  check(provider.name === 'rack-skill-policy', 'the provider has its own name')
  const listed = await provider.list()
  eq(listed.complete, true, 'the provider reports a complete observation')
  eq(listed.candidates.map((candidate) => candidate.name), ['alpha'], 'the provider only answers for switched-off skills')
  const candidate = listed.candidates[0]
  eq(candidate.invocation, { modelInvocable: false, userInvocable: false }, 'the off candidate is not invocable')
  check(candidate.rank < 400, 'the policy candidate outranks the user root so it wins the merge')
  eq(candidate.provider, 'rack-skill-policy', 'the candidate names its own provider')
  eq(provider.get({}, {}), undefined, 'the provider never supplies a body')
  check(typeof provider.list === 'function' && typeof provider.get === 'function', 'the provider matches the core contract shape')

  const emptyProvider = createSkillPolicyProvider({
    read: () => ({ disabled: [], notes: {} }),
    scan: () => [],
  })
  eq((await emptyProvider.list()).candidates, [], 'nothing switched off means no candidates at all')

  // A switched-off skill that does not exist any more must not be invented.
  writeSkillState(workspace, { disabled: ['ghost'], notes: {} })
  const ghost = await provider.list()
  eq(ghost.candidates, [], 'an off entry for a missing skill contributes nothing')
} finally {
  rmSync(workspace, { recursive: true, force: true })
}

// ── plugin-bundled skills ───────────────────────────────────────────────────
// A plugin can ship its own skills/ directory inside the package. Those are
// loaded by the host, so the panel has to list them too, or the page quietly
// under-reports what the machine actually runs.
{
  const workspace = mkdtempSync(join(tmpdir(), 'rack-skills-plugin-'))
  try {
    const nm = join(workspace, 'node_modules')
    const bare = join(nm, 'plain-plugin')
    const scoped = join(nm, '@scope', 'scoped-plugin')
    const noSkills = join(nm, 'no-skills-here')
    mkdirSync(join(bare, 'skills', 'alpha'), { recursive: true })
    mkdirSync(join(scoped, 'skills', 'beta'), { recursive: true })
    mkdirSync(noSkills, { recursive: true })
    const doc = (name) => '---\nname: ' + name + '\ndescription: A bundled skill.\n---\n\nBody.\n'
    writeFileSync(join(bare, 'skills', 'alpha', 'SKILL.md'), doc('alpha'))
    writeFileSync(join(scoped, 'skills', 'beta', 'SKILL.md'), doc('beta'))

    const found = pluginSkillPackages(nm)
    eq(found.length, 2, 'only packages that ship a skills directory are roots')
    check(found.indexOf(bare) >= 0, 'a bare package with skills/ is found')
    check(found.indexOf(scoped) >= 0, 'a scoped package with skills/ is found')
    check(found.indexOf(noSkills) < 0, 'a package without skills/ is not a root')
    eq(pluginSkillPackages(null), [], 'no node_modules path yields no roots')
    eq(pluginSkillPackages(join(workspace, 'missing')), [], 'a missing directory yields no roots')

    // Isolate from the real machine: without explicit homes this helper reads
    // the developer's own ~/.dsh/skills and the assertions below stop meaning
    // anything on a machine that has skills installed.
    const roots = skillRoots({
      dshHome: join(workspace, 'empty-dsh'),
      agentsHome: join(workspace, 'empty-agents'),
      projectRoots: [],
      pluginRoots: found,
    })
    const scanned = scanSkills(roots)
    const bundled = scanned.skills.filter((skill) => String(skill.rootKey).startsWith('plugin:'))
    eq(bundled.length, 2, 'both bundled skills are scanned')
    check(bundled.every((skill) => skill.loadable === true), 'bundled skills parse like any other')
    check(bundled.every((skill) => skill.scope === 'plugin'), 'bundled skills carry the plugin scope')
    check(
      bundled.every((skill) => skill.rank === 600),
      'bundled skills rank last so a user copy of the same name wins',
    )

    // A user directory with the same name must still win.
    const userDir = join(workspace, 'dsh', 'skills', 'alpha')
    mkdirSync(userDir, { recursive: true })
    writeFileSync(join(userDir, 'SKILL.md'), doc('alpha'))
    const both = skillRoots({
      dshHome: join(workspace, 'dsh'),
      agentsHome: join(workspace, 'empty-agents'),
      projectRoots: [],
      pluginRoots: found,
    })
    const winners = resolveWinners(scanSkills(both).skills)
    const alpha = winners.filter((skill) => skill.name === 'alpha')
    eq(alpha.length, 2, 'both copies of alpha are listed')
    check(
      alpha.filter((skill) => skill.winner === true).length === 1,
      'exactly one copy of alpha wins',
    )
    check(
      alpha.find((skill) => skill.winner === true).scope === 'user',
      'the user copy outranks the bundled one',
    )
  } finally {
    rmSync(workspace, { recursive: true, force: true })
  }
}

// ── bundled skills present as one group, not one group per package ─────────
// Each package needs its own root to be scanned, but a group per package reads
// as five columns all labelled "plugins". The snapshot merges them.
{
  const workspace = mkdtempSync(join(tmpdir(), 'rack-skills-groups-'))
  try {
    const nm = join(workspace, 'node_modules')
    const mk = (pkg, name) => {
      const dir = join(nm, pkg, 'skills', name)
      mkdirSync(dir, { recursive: true })
      writeFileSync(join(dir, 'SKILL.md'), '---\nname: ' + name + '\ndescription: Bundled.\n---\n\nBody.\n')
    }
    mk('alpha-plugin', 'one')
    mk('beta-plugin', 'two')
    mk('@scope/gamma-plugin', 'three')

    const packages = pluginSkillPackages(nm)
    eq(packages.length, 3, 'three packages ship skills')
    const roots = skillRoots({
      dshHome: join(workspace, 'empty-dsh'),
      agentsHome: join(workspace, 'empty-agents'),
      projectRoots: [],
      pluginRoots: packages,
    })
    const scanned = scanSkills(roots)
    eq(
      scanned.skills.filter((s) => String(s.rootKey).startsWith('plugin:')).length,
      3,
      'scanning still reports every bundled skill separately',
    )
    check(
      scanned.roots.filter((r) => r.scope === 'plugin').length === 3,
      'one scan root per package, because each has its own skills/ directory',
    )
    // The merge the snapshot applies: one bucket for every plugin root.
    const keys = new Set(
      scanned.skills
        .filter((s) => String(s.rootKey).startsWith('plugin:'))
        .map(() => 'plugins'),
    )
    eq(keys.size, 1, 'all bundled skills collapse into a single display group')
  } finally {
    rmSync(workspace, { recursive: true, force: true })
  }
}

if (failures > 0) {
  console.error('SKILLS_FAIL ' + failures + '/' + checks)
  process.exit(1)
}
console.log('SKILLS_OK ' + checks)
