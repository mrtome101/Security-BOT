/**
 * Tome • Security Bot
 * ------------------------------------------------------------
 * AutoMod, Anti-Nuke, Anti-Raid, verification and moderation
 * tools for a single Discord community.
 *
 * Setup
 *   1. Set the TOKEN environment variable (recommended), or
 *      paste the token into the TOKEN constant below.
 *   2. Give the bot a role at the TOP of the role list with:
 *      Administrator (or Ban, Kick, Manage Roles/Channels/Webhooks,
 *      Timeout Members, Manage Messages, View Audit Log).
 *   3. Run /audit in your server to verify the setup.
 */

const fs = require('fs');
const path = require('path');
const {
  Client,
  GatewayIntentBits,
  Events,
  EmbedBuilder,
  PermissionFlagsBits,
  AuditLogEvent,
  ChannelType,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  ModalBuilder,
  TextInputBuilder,
  TextInputStyle,
  MessageFlags,
  GuildVerificationLevel,
  GuildExplicitContentFilter,
  SlashCommandBuilder,
  InteractionContextType,
  ActivityType
} = require('discord.js');

// ============================================================
//  CONFIGURATION
// ============================================================
// Never commit a real token. Prefer the TOKEN environment variable.
const TOKEN = process.env.TOKEN || 'YOUR_NEW_TOKEN_HERE';

const PREFIX = '/';
const COLOR = 0x4b4b4b; // embed side-line colour
const ALERT = COLOR; // alerts use the same colour on purpose
const FOOTER = 'Tome • Security';

// Detection thresholds
const NUKE_LIMIT = 3; // destructive actions...
const NUKE_WINDOW = 10 * 1000; // ...within 10 seconds
const RAID_JOINS = 5; // joins...
const RAID_WINDOW = 10 * 1000; // ...within 10 seconds
const RAID_MODE_TIME = 2 * 60 * 1000; // automatic raid mode duration
const SPAM = { messages: 5, windowMs: 5 * 1000, timeoutMs: 5 * 60 * 1000 };
const DUPLICATE = { count: 3, windowMs: 15 * 1000, minLength: 4 };
const STRIKES = { count: 3, windowMs: 10 * 60 * 1000, timeoutMs: 10 * 60 * 1000 };
const CAPTCHA_TTL = 5 * 60 * 1000;

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildModeration,
    GatewayIntentBits.GuildWebhooks,
    GatewayIntentBits.GuildEmojisAndStickers
  ]
});

// ============================================================
//  STORAGE  (data/data.json)
// ============================================================
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'data.json');
let db = { guilds: {} };

try {
  db = { guilds: {}, ...JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) };
} catch (e) {
  if (e.code !== 'ENOENT') console.error('Could not read data file, starting empty:', e.message);
}

/** Writes the database atomically (temp file + rename) so a crash cannot corrupt it. */
function writeData() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = `${DATA_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

let saveTimer = null;
/** Debounced save: many changes in a short time result in a single write. */
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try {
      writeData();
    } catch (e) {
      console.error('Save error:', e.message);
    }
  }, 400);
}

/** Saves immediately (used on shutdown so no pending change is lost). */
function flushSave() {
  clearTimeout(saveTimer);
  try {
    writeData();
  } catch (e) {
    console.error('Save error:', e.message);
  }
}

// feature key -> [description, enabled by default]
const FEATURES = {
  antilink: ['Block links (except allowed domains)', false],
  antiinvite: ['Block Discord invite links', true],
  antiscam: ['Block scam / phishing / fake-nitro links', true],
  antispam: ['Block message spam (5 msgs / 5s)', true],
  antiduplicate: ['Block repeated identical messages', true],
  antimention: ['Block mass mentions & @everyone abuse', true],
  anticaps: ['Block excessive CAPS', false],
  antiemoji: ['Block emoji spam (10+ emojis)', false],
  antizalgo: ['Block zalgo / glitch text', false],
  antibadword: ['Block words from the badword list', false],
  antighostping: ['Expose ghost pings', true],
  antiraid: ['Detect join floods (5 joins / 10s)', true],
  antinoavatar: ['Kick new members with no avatar', false],
  antibot: ['Block unauthorised bot additions', true],
  antinuke: ['Protect channels, roles, perms, webhooks, bans', true],
  antifile: ['Block dangerous files (.exe .scr .bat .apk ...)', true],
  antishortener: ['Block URL shorteners & IP-grabber links', true],
  antiwall: ['Block walls of text / newline spam', false],
  msglog: ['Log deleted & edited messages', true],
  joinlog: ['Log member joins & leaves', true],
  modlog: ['Log bans, timeouts, channel & role changes', true]
};

/** Returns the guild's config, filling in any missing defaults. */
function getConfig(guildId) {
  if (!db.guilds[guildId]) db.guilds[guildId] = {};
  const g = db.guilds[guildId];
  if (!g.features) g.features = {};
  for (const [k, [, def]] of Object.entries(FEATURES)) {
    if (typeof g.features[k] !== 'boolean') g.features[k] = def;
  }
  for (const k of ['whitelist', 'badWords', 'allowedDomains', 'bypassChannels', 'bypassRoles', 'allowedBots']) {
    if (!Array.isArray(g[k])) g[k] = [];
  }
  if (!g.warns || typeof g.warns !== 'object' || Array.isArray(g.warns)) g.warns = {};
  if (g.logChannel === undefined) g.logChannel = null;
  if (g.verifyRole === undefined) g.verifyRole = null;
  if (typeof g.minAccountAgeDays !== 'number') g.minAccountAgeDays = 0;
  if (!g.punishment) g.punishment = 'ban';
  if (!g.touched || typeof g.touched !== 'object') g.touched = {}; // protections an admin switched manually
  if (g.panicSnapshot === undefined) g.panicSnapshot = null; // protection states saved while panic mode is on
  return g;
}

/**
 * Turns a protection on/off. The choice is remembered as "manual" (so /harden
 * never overrides it) and written to disk immediately.
 */
function setFeature(cfg, key, on) {
  cfg.features[key] = on;
  cfg.touched[key] = true;
  if (cfg.panicSnapshot) cfg.panicSnapshot[key] = on; // keep the choice after panic mode ends
  flushSave();
}

// ============================================================
//  HELPERS
// ============================================================
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const clip = (t, n = 1000) => String(t || '').slice(0, n) || '—';

/** Plain text -> embed with the standard side line and footer. */
function box(text) {
  return new EmbedBuilder().setColor(COLOR).setDescription(text).setFooter({ text: FOOTER });
}
function asEmbed(payload) {
  return typeof payload === 'string' ? { embeds: [box(payload)] } : payload;
}

// Display names for the protections
const LABELS = {
  antilink: 'Anti-Link', antiinvite: 'Anti-Invite', antiscam: 'Anti-Scam', antispam: 'Anti-Spam',
  antiduplicate: 'Anti-Duplicate', antimention: 'Anti-Mention', anticaps: 'Anti-Caps', antiemoji: 'Anti-Emoji',
  antizalgo: 'Anti-Zalgo', antibadword: 'Anti-Badword', antighostping: 'Anti-Ghost-Ping', antiraid: 'Anti-Raid',
  antinoavatar: 'Anti-NoAvatar', antibot: 'Anti-Bot', antinuke: 'Anti-Nuke', antifile: 'Anti-File',
  antishortener: 'Anti-Shortener', antiwall: 'Anti-Wall', msglog: 'Message Log', joinlog: 'Join Log', modlog: 'Mod Log'
};
const label = (k) => LABELS[k] || k;
const tag = (on) => (on ? '`ON `' : '`OFF`');

/** Standard styled embed used by every command response. */
function emb(title, description, fields = []) {
  const e = new EmbedBuilder().setColor(COLOR).setTitle(title).setFooter({ text: FOOTER }).setTimestamp();
  if (description) e.setDescription(String(description).slice(0, 4000));
  if (fields.length) e.addFields(fields);
  return e;
}
const success = (title, description, fields) => ({ embeds: [emb(title, description, fields)] });
const failure = (description, title = 'Action failed') => ({ embeds: [emb(title, description)] });
const info = (title, description, fields) => ({ embeds: [emb(title, description, fields)] });
const usage = (syntax, example) => ({
  embeds: [emb('Usage', `\`${syntax}\``, example ? [{ name: 'Example', value: `\`${example}\`` }] : [])]
});

/** Sends an embed DM; silently ignored when the user's DMs are closed. */
async function sendDM(user, title, fields) {
  try {
    const embed = new EmbedBuilder().setColor(COLOR).setTitle(title).addFields(fields).setTimestamp();
    await user.send({ embeds: [embed] });
  } catch (err) {}
}

/** Posts an entry to the guild's configured log channel (if any). */
async function log(guild, title, fields, color = ALERT) {
  const cfg = getConfig(guild.id);
  if (!cfg.logChannel) return;
  const channel = guild.channels.cache.get(cfg.logChannel);
  if (!channel) return;
  try {
    const embed = new EmbedBuilder()
      .setColor(color)
      .setTitle(title)
      .addFields(fields)
      .setFooter({ text: FOOTER })
      .setTimestamp();
    await channel.send({ embeds: [embed] });
  } catch (e) {}
}

/** Owner, whitelisted users and the bot itself are never punished. */
function isTrusted(guild, userId) {
  const cfg = getConfig(guild.id);
  return userId === client.user.id || userId === guild.ownerId || cfg.whitelist.includes(userId);
}

/** Exempt from AutoMod: trusted users + Administrators. */
function isAutoModExempt(member) {
  if (!member) return true;
  if (isTrusted(member.guild, member.id)) return true;
  return member.permissions.has(PermissionFlagsBits.Administrator);
}

/** True when the message is in a bypassed channel/category or sent by a bypassed role. */
function isBypassed(message) {
  const cfg = getConfig(message.guild.id);
  const ch = message.channel;
  if (cfg.bypassChannels.includes(ch.id)) return true;
  if (ch.parentId && cfg.bypassChannels.includes(ch.parentId)) return true;
  return message.member.roles.cache.some((r) => cfg.bypassRoles.includes(r.id));
}

async function getMember(message, arg) {
  const mentioned = message.mentions.members.first();
  if (mentioned) return mentioned;
  if (arg && /^\d{15,25}$/.test(arg)) return message.guild.members.fetch(arg).catch(() => null);
  return null;
}

/** Finds who performed an action by reading the audit log (events fire before the log entry appears). */
async function getExecutor(guild, type, targetId = null) {
  await sleep(700); // audit log can lag a little
  try {
    const logs = await guild.fetchAuditLogs({ type, limit: 6 });
    const entry = logs.entries.find(
      (e) => Date.now() - e.createdTimestamp < 8000 && (!targetId || e.target?.id === targetId)
    );
    return entry ? { executor: entry.executor, entry } : null;
  } catch (e) {
    return null; // missing "View Audit Log" permission
  }
}

/** Applies the configured punishment (ban / kick, with fallbacks). Returns a short result text. */
async function punish(guild, userId, reason) {
  const cfg = getConfig(guild.id);
  const member = await guild.members.fetch(userId).catch(() => null);
  if (!member) return 'not found';
  try {
    if (cfg.punishment === 'kick' && member.kickable) {
      await member.kick(reason);
      return 'kicked';
    }
    if (member.bannable) {
      await member.ban({ reason });
      return 'banned';
    }
    if (member.manageable) {
      await member.roles.set([], reason);
      return 'roles removed';
    }
  } catch (e) {}
  return 'failed (move my role higher)';
}

const DANGEROUS_PERMS = [
  PermissionFlagsBits.Administrator,
  PermissionFlagsBits.ManageGuild,
  PermissionFlagsBits.ManageRoles,
  PermissionFlagsBits.ManageChannels,
  PermissionFlagsBits.BanMembers,
  PermissionFlagsBits.KickMembers,
  PermissionFlagsBits.ManageWebhooks
];

// ============================================================
//  ANTI-NUKE
// ============================================================
const nukeTracker = new Map();

async function nukeGuard(guild, type, targetId, label, restore) {
  const cfg = getConfig(guild.id);
  if (!cfg.features.antinuke) return;

  const res = await getExecutor(guild, type, targetId);
  if (!res) return;
  const { executor } = res;
  if (!executor || isTrusted(guild, executor.id)) return;

  const key = `${guild.id}:${executor.id}`;
  const now = Date.now();
  const list = (nukeTracker.get(key) || []).filter((e) => now - e.t < NUKE_WINDOW);
  list.push({ t: now, label, restore });
  nukeTracker.set(key, list);

  await log(guild, 'Anti-Nuke: Suspicious Action', [
    { name: 'User', value: `${executor.tag} (${executor.id})`, inline: true },
    { name: 'Action', value: label, inline: true },
    { name: 'Count', value: `${list.length}/${NUKE_LIMIT}`, inline: true }
  ]);

  if (list.length >= NUKE_LIMIT) {
    nukeTracker.delete(key);
    const result = await punish(guild, executor.id, `Anti-Nuke: ${label}`);
    for (const e of list) {
      if (e.restore) await e.restore().catch(() => {});
    }
    await log(guild, 'Anti-Nuke: User Punished', [
      { name: 'User', value: `${executor.tag} (${executor.id})`, inline: true },
      { name: 'Result', value: result, inline: true },
      { name: 'Restored', value: 'Deleted channels/roles/emojis & bans were reverted where possible.' }
    ]);
  }
}

client.on(Events.ChannelDelete, (channel) => {
  if (!channel.guild) return;
  nukeGuard(channel.guild, AuditLogEvent.ChannelDelete, channel.id, `Deleted channel #${channel.name}`, () =>
    channel.clone()
  );
});

client.on(Events.ChannelCreate, (channel) => {
  if (!channel.guild) return;
  nukeGuard(channel.guild, AuditLogEvent.ChannelCreate, channel.id, `Created channel #${channel.name}`, () =>
    channel.delete('Anti-Nuke revert')
  );
});

client.on(Events.GuildRoleDelete, (role) => {
  nukeGuard(role.guild, AuditLogEvent.RoleDelete, role.id, `Deleted role @${role.name}`, () =>
    role.guild.roles.create({
      name: role.name,
      color: role.color,
      hoist: role.hoist,
      mentionable: role.mentionable,
      permissions: role.permissions,
      reason: 'Anti-Nuke restore'
    })
  );
});

client.on(Events.GuildRoleCreate, (role) => {
  nukeGuard(role.guild, AuditLogEvent.RoleCreate, role.id, `Created role @${role.name}`, () =>
    role.delete('Anti-Nuke revert')
  );
});

client.on(Events.GuildBanAdd, (ban) => {
  nukeGuard(ban.guild, AuditLogEvent.MemberBanAdd, ban.user.id, `Banned ${ban.user.tag}`, () =>
    ban.guild.members.unban(ban.user.id, 'Anti-Nuke revert')
  );
});

client.on(Events.GuildMemberRemove, async (member) => {
  const res = await getExecutor(member.guild, AuditLogEvent.MemberKick, member.id);
  if (!res) return; // the member left on their own
  nukeGuard(member.guild, AuditLogEvent.MemberKick, member.id, `Kicked ${member.user.tag}`, null);
});

client.on(Events.GuildEmojiDelete, (emoji) => {
  nukeGuard(emoji.guild, AuditLogEvent.EmojiDelete, emoji.id, `Deleted emoji :${emoji.name}:`, () =>
    emoji.guild.emojis.create({ attachment: emoji.imageURL(), name: emoji.name })
  );
});

// Role created WITH dangerous permissions
client.on(Events.GuildRoleCreate, async (role) => {
  const cfg = getConfig(role.guild.id);
  if (!cfg.features.antinuke || role.managed) return;
  if (!DANGEROUS_PERMS.some((p) => role.permissions.has(p))) return;

  const res = await getExecutor(role.guild, AuditLogEvent.RoleCreate, role.id);
  if (!res || isTrusted(role.guild, res.executor.id)) return;

  await role.delete('Anti-Nuke: role created with dangerous permissions').catch(() => {});
  const result = await punish(role.guild, res.executor.id, 'Anti-Nuke: created a role with dangerous permissions');
  await log(role.guild, 'Anti-Nuke: Dangerous Role Creation Blocked', [
    { name: 'User', value: `${res.executor.tag} (${res.executor.id})`, inline: true },
    { name: 'Role', value: `${role.name}`, inline: true },
    { name: 'Result', value: result, inline: true }
  ]);
});

// Role gains a dangerous permission
client.on(Events.GuildRoleUpdate, async (oldRole, newRole) => {
  const cfg = getConfig(newRole.guild.id);
  if (!cfg.features.antinuke) return;
  const gained = DANGEROUS_PERMS.some((p) => !oldRole.permissions.has(p) && newRole.permissions.has(p));
  if (!gained) return;

  const res = await getExecutor(newRole.guild, AuditLogEvent.RoleUpdate, newRole.id);
  if (!res || isTrusted(newRole.guild, res.executor.id)) return;

  await newRole.setPermissions(oldRole.permissions, 'Anti-Nuke: dangerous permission added').catch(() => {});
  const result = await punish(newRole.guild, res.executor.id, 'Anti-Nuke: gave dangerous permissions to a role');
  await log(newRole.guild, 'Anti-Nuke: Dangerous Permission Blocked', [
    { name: 'User', value: `${res.executor.tag} (${res.executor.id})`, inline: true },
    { name: 'Role', value: `${newRole.name}`, inline: true },
    { name: 'Result', value: result, inline: true }
  ]);
});

// Member receives a role with dangerous permissions
client.on(Events.GuildMemberUpdate, async (oldM, newM) => {
  const guild = newM.guild;
  const cfg = getConfig(guild.id);
  if (!cfg.features.antinuke) return;

  const added = newM.roles.cache.filter((r) => !oldM.roles.cache.has(r.id));
  const risky = added.filter((r) => DANGEROUS_PERMS.some((p) => r.permissions.has(p)));
  if (!risky.size) return;

  const res = await getExecutor(guild, AuditLogEvent.MemberRoleUpdate, newM.id);
  if (!res || isTrusted(guild, res.executor.id)) return;

  await newM.roles.remove(risky, 'Anti-Nuke: dangerous role given').catch(() => {});
  const result = await punish(guild, res.executor.id, 'Anti-Nuke: gave a dangerous role');
  await log(guild, 'Anti-Nuke: Dangerous Role Blocked', [
    { name: 'Given by', value: `${res.executor.tag} (${res.executor.id})`, inline: true },
    { name: 'To', value: `${newM.user.tag}`, inline: true },
    { name: 'Roles', value: risky.map((r) => r.name).join(', ') },
    { name: 'Result', value: result }
  ]);
});

// Server name changed
client.on(Events.GuildUpdate, async (oldG, newG) => {
  const cfg = getConfig(newG.id);
  if (!cfg.features.antinuke || oldG.name === newG.name) return;
  const res = await getExecutor(newG, AuditLogEvent.GuildUpdate);
  if (!res || isTrusted(newG, res.executor.id)) return;

  await newG.setName(oldG.name, 'Anti-Nuke revert').catch(() => {});
  const result = await punish(newG, res.executor.id, 'Anti-Nuke: changed server name');
  await log(newG, 'Anti-Nuke: Server Name Change Reverted', [
    { name: 'User', value: `${res.executor.tag}`, inline: true },
    { name: 'Result', value: result, inline: true }
  ]);
});

// Unauthorised webhook
client.on(Events.WebhooksUpdate, async (channel) => {
  const guild = channel.guild;
  if (!guild) return;
  const cfg = getConfig(guild.id);
  if (!cfg.features.antinuke) return;

  const res = await getExecutor(guild, AuditLogEvent.WebhookCreate);
  if (!res || isTrusted(guild, res.executor.id)) return;

  try {
    const hooks = await channel.fetchWebhooks();
    const hook = hooks.get(res.entry.target?.id);
    if (hook) await hook.delete('Anti-Nuke: unauthorised webhook');
  } catch (e) {}

  const result = await punish(guild, res.executor.id, 'Anti-Nuke: created a webhook');
  await log(guild, 'Anti-Nuke: Webhook Blocked', [
    { name: 'User', value: `${res.executor.tag} (${res.executor.id})`, inline: true },
    { name: 'Channel', value: `<#${channel.id}>`, inline: true },
    { name: 'Result', value: result, inline: true }
  ]);
});

// ============================================================
//  MEMBER JOIN: Anti-Bot / Anti-New-Account / Anti-NoAvatar / Anti-Raid
// ============================================================
const joinLog = new Map();
const raidUntil = new Map();

client.on(Events.GuildMemberAdd, async (member) => {
  const guild = member.guild;
  const cfg = getConfig(guild.id);

  // ---------- Anti-Bot ----------
  if (member.user.bot) {
    if (!cfg.features.antibot || cfg.allowedBots.includes(member.id)) return;
    const res = await getExecutor(guild, AuditLogEvent.BotAdd, member.id);
    const adder = res?.executor;
    if (adder && isTrusted(guild, adder.id)) return;

    await member.kick('Anti-Bot: unauthorised bot').catch(() => {});
    let result = 'n/a';
    if (adder) result = await punish(guild, adder.id, 'Anti-Bot: added an unauthorised bot');
    await log(guild, 'Anti-Bot: Bot Removed', [
      { name: 'Bot', value: `${member.user.tag} (${member.id})`, inline: true },
      { name: 'Added by', value: adder ? `${adder.tag}` : 'Unknown', inline: true },
      { name: 'Punishment', value: result, inline: true }
    ]);
    return;
  }

  if (isTrusted(guild, member.id)) return;

  // ---------- Anti-New-Account ----------
  if (cfg.minAccountAgeDays > 0) {
    const ageDays = (Date.now() - member.user.createdTimestamp) / 86400000;
    if (ageDays < cfg.minAccountAgeDays) {
      await sendDM(member.user, 'Account too new', [
        { name: 'Server', value: guild.name },
        { name: 'Reason', value: `Your account must be at least ${cfg.minAccountAgeDays} day(s) old to join.` }
      ]);
      await member.kick('Anti-New-Account').catch(() => {});
      await log(guild, 'Anti-New-Account: Kicked', [
        { name: 'User', value: `${member.user.tag} (${member.id})`, inline: true },
        { name: 'Account age', value: `${ageDays.toFixed(1)} day(s)`, inline: true }
      ]);
      return;
    }
  }

  // ---------- Anti-NoAvatar ----------
  if (cfg.features.antinoavatar && !member.user.avatar) {
    await sendDM(member.user, 'Profile picture required', [
      { name: 'Server', value: guild.name },
      { name: 'Reason', value: 'Please set a profile picture and join again.' }
    ]);
    await member.kick('Anti-NoAvatar').catch(() => {});
    await log(guild, 'Anti-NoAvatar: Kicked', [{ name: 'User', value: `${member.user.tag} (${member.id})` }]);
    return;
  }

  // ---------- Anti-Raid ----------
  if (!cfg.features.antiraid) return;
  const now = Date.now();

  if ((raidUntil.get(guild.id) || 0) > now) {
    await sendDM(member.user, 'Server is under protection', [
      { name: 'Server', value: guild.name },
      { name: 'Reason', value: 'Raid protection is active. Please try again in a few minutes.' }
    ]);
    await member.kick('Anti-Raid: raid mode active').catch(() => {});
    return;
  }

  const list = (joinLog.get(guild.id) || []).filter((j) => now - j.t < RAID_WINDOW);
  list.push({ id: member.id, t: now });
  joinLog.set(guild.id, list);

  if (list.length >= RAID_JOINS) {
    raidUntil.set(guild.id, now + RAID_MODE_TIME);
    joinLog.set(guild.id, []);
    let kicked = 0;
    for (const j of list) {
      const m = await guild.members.fetch(j.id).catch(() => null);
      if (m && m.kickable && !isTrusted(guild, m.id)) {
        await m.kick('Anti-Raid: join flood').catch(() => {});
        kicked++;
      }
    }
    await log(guild, 'Anti-Raid: Raid Detected', [
      { name: 'Joins', value: `${list.length} in ${RAID_WINDOW / 1000}s`, inline: true },
      { name: 'Kicked', value: `${kicked}`, inline: true },
      { name: 'Raid mode', value: `Active for ${RAID_MODE_TIME / 60000} minutes (new joins are kicked)` }
    ]);
  }
});

// ============================================================
//  AUTOMOD
// ============================================================
const INVITE_RE = /(discord\.gg|discord(app)?\.com\/invite|dsc\.gg)\/[a-z0-9-]+/i;
const SCAM_RE =
  /(free\s*nitro|nitro\s*gift|claim\s+your\s+(nitro|gift|reward)|discord[-.]?gifts?\.|discord[-.]?nitro|dlscord|disc0rd|steamcommunnity|steamcomrnunity|steancommunity|airdrop.{0,30}(claim|wallet)|@everyone.{0,40}(nitro|giveaway).{0,40}https?:)/i;
const ZALGO_RE = /[\u0300-\u036f\u0483-\u0489\u0610-\u061a\u064b-\u065f]{4,}/;
const EMOJI_RE = /<a?:\w+:\d+>|\p{Extended_Pictographic}/gu;
const SHORTENER_RE =
  /(?:^|[\s/@(<.])(?:bit\.ly|tinyurl\.com|goo\.gl|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|ow\.ly|buff\.ly|tiny\.cc|t\.ly|v\.gd|shorte\.st|adf\.ly|grabify\.link|iplogger\.(?:org|com|ru)|2no\.co|yip\.su|blasze\.com|stopify\.co|joinmy\.site|lovebird\.guru|trulove\.guru|dateing\.club|shrekis\.life|datauth\.xyz|gyazo\.nl|maper\.info|ezstat\.ru|linkbucks\.com)(?![a-z0-9-])/i;
const DANGEROUS_FILE_RE = /\.(exe|scr|bat|cmd|com|msi|msix|appx|jar|apk|vbs|vbe|jse|wsf|wsh|ps1|lnk|hta|dll|reg|pif|cpl|scf)$/i;
const botDeleted = new Set(); // messages deleted by the bot itself (avoids duplicate logs)

const spamTracker = new Map();
const dupTracker = new Map();
const strikeTracker = new Map();

function extractHosts(text) {
  const hosts = [];
  const re = /(?:https?:\/\/|www\.)([^\s\/?#<>]+)/gi;
  let m;
  while ((m = re.exec(text))) hosts.push(m[1].toLowerCase().replace(/^www\./, ''));
  return hosts;
}

/** Deletes the offending message, warns the user, logs it and applies strikes / timeouts. */
async function violation(message, reason, timeoutMs = 0, feature = null) {
  botDeleted.add(message.id);
  setTimeout(() => botDeleted.delete(message.id), 30000);
  await message.delete().catch(() => {});
  const warnEmbed = new EmbedBuilder()
    .setColor(COLOR)
    .setDescription(`AutoMod: ${reason}`)
    .setFooter({ text: feature ? `${FOOTER} • ${label(feature)}` : FOOTER });
  const warn = await message.channel.send({ content: `${message.author}`, embeds: [warnEmbed] }).catch(() => null);
  if (warn) setTimeout(() => warn.delete().catch(() => {}), 5000);

  await log(message.guild, 'AutoMod', [
    { name: 'User', value: `${message.author.tag} (${message.author.id})`, inline: true },
    { name: 'Channel', value: `<#${message.channel.id}>`, inline: true },
    { name: 'Reason', value: reason },
    { name: 'Protection', value: feature ? `${label(feature)} — disable with \`/${feature} off\`` : 'AutoMod' },
    { name: 'Message', value: (message.content || '—').slice(0, 900) }
  ]);

  if (timeoutMs && message.member?.moderatable) {
    await message.member.timeout(timeoutMs, `AutoMod: ${reason}`).catch(() => {});
    return;
  }

  // Repeated violations = timeout
  const key = `${message.guild.id}:${message.author.id}`;
  const now = Date.now();
  const strikes = (strikeTracker.get(key) || []).filter((t) => now - t < STRIKES.windowMs);
  strikes.push(now);
  strikeTracker.set(key, strikes);
  if (strikes.length >= STRIKES.count && message.member?.moderatable) {
    strikeTracker.delete(key);
    await message.member.timeout(STRIKES.timeoutMs, `AutoMod: ${STRIKES.count} violations`).catch(() => {});
    await log(message.guild, `AutoMod: Timeout (${STRIKES.count} strikes)`, [
      { name: 'User', value: `${message.author.tag}`, inline: true },
      { name: 'Duration', value: `${STRIKES.timeoutMs / 60000}m`, inline: true }
    ]);
  }
}

/** Runs every enabled AutoMod check. Returns true when the message was actioned. */
async function runAutoMod(message, isEdit = false) {
  const cfg = getConfig(message.guild.id);
  const f = cfg.features;
  const content = message.content || '';
  const key = `${message.guild.id}:${message.author.id}`;
  const now = Date.now();

  // ----- Anti-Spam -----
  if (f.antispam && !isEdit) {
    const list = (spamTracker.get(key) || []).filter((m) => now - m.t < SPAM.windowMs);
    list.push({ t: now, id: message.id, channel: message.channel });
    spamTracker.set(key, list);
    if (list.length >= SPAM.messages) {
      spamTracker.delete(key);
      const ids = list.filter((m) => m.channel.id === message.channel.id).map((m) => m.id);
      await message.channel.bulkDelete(ids, true).catch(() => {});
      if (message.member?.moderatable) await message.member.timeout(SPAM.timeoutMs, 'AutoMod: spam').catch(() => {});
      const warn = await message.channel
        .send({ content: `${message.author}`, embeds: [box(`Muted for **spamming** (${SPAM.timeoutMs / 60000}m).`)] })
        .catch(() => null);
      if (warn) setTimeout(() => warn.delete().catch(() => {}), 5000);
      await log(message.guild, 'Anti-Spam: Timeout', [
        { name: 'User', value: `${message.author.tag} (${message.author.id})`, inline: true },
        { name: 'Channel', value: `<#${message.channel.id}>`, inline: true }
      ]);
      return true;
    }
  }

  // ----- Anti-Duplicate -----
  if (f.antiduplicate && !isEdit && content.length >= DUPLICATE.minLength) {
    const norm = content.toLowerCase().trim();
    const list = (dupTracker.get(key) || []).filter((m) => now - m.t < DUPLICATE.windowMs && m.c === norm);
    list.push({ t: now, c: norm });
    dupTracker.set(key, list);
    if (list.length >= DUPLICATE.count) {
      dupTracker.delete(key);
      await violation(message, 'Please do not repeat the same message.', 0, 'antiduplicate');
      return true;
    }
  }

  // ----- Anti-Scam (compromised accounts / phishing) -----
  if (f.antiscam && SCAM_RE.test(content)) {
    await violation(message, 'Scam / phishing content detected.', 60 * 60 * 1000, 'antiscam');
    return true;
  }

  // ----- Anti-Shortener / IP-grabber -----
  if (f.antishortener && SHORTENER_RE.test(content)) {
    await violation(message, 'URL shorteners / IP-grabber links are not allowed.', 10 * 60 * 1000, 'antishortener');
    return true;
  }

  // ----- Anti-File (malware-type attachments) -----
  if (f.antifile && message.attachments.size) {
    const bad = message.attachments.find((a) => DANGEROUS_FILE_RE.test(a.name || ''));
    if (bad) {
      await violation(message, `Dangerous file type blocked (${bad.name}).`, 10 * 60 * 1000, 'antifile');
      return true;
    }
  }

  // ----- Anti-Invite -----
  if (f.antiinvite && INVITE_RE.test(content)) {
    await violation(message, 'Discord invite links are not allowed here.', 0, 'antiinvite');
    return true;
  }

  // ----- Anti-Link -----
  if (f.antilink) {
    const hosts = extractHosts(content);
    const bad = hosts.some((h) => !cfg.allowedDomains.some((d) => h === d || h.endsWith('.' + d)));
    if (bad) {
      await violation(message, 'Links are not allowed here.', 0, 'antilink');
      return true;
    }
  }

  // ----- Anti-Mention -----
  if (f.antimention) {
    const everyoneAbuse =
      /@(everyone|here)/.test(content) && !message.member.permissions.has(PermissionFlagsBits.MentionEveryone);
    if (message.mentions.users.size >= 5 || message.mentions.roles.size >= 4 || everyoneAbuse) {
      await violation(message, 'Mass mentions are not allowed.', 10 * 60 * 1000, 'antimention');
      return true;
    }
  }

  // ----- Anti-Caps -----
  if (f.anticaps) {
    const letters = content.replace(/[^a-zA-Z]/g, '');
    if (letters.length >= 10 && letters.replace(/[^A-Z]/g, '').length / letters.length > 0.7) {
      await violation(message, 'Please do not use excessive CAPS.', 0, 'anticaps');
      return true;
    }
  }

  // ----- Anti-Emoji -----
  if (f.antiemoji) {
    const count = (content.match(EMOJI_RE) || []).length;
    if (count >= 10) {
      await violation(message, 'Too many emojis in one message.', 0, 'antiemoji');
      return true;
    }
  }

  // ----- Anti-Zalgo -----
  if (f.antizalgo && ZALGO_RE.test(content)) {
    await violation(message, 'Zalgo / glitch text is not allowed.', 0, 'antizalgo');
    return true;
  }

  // ----- Anti-Wall (huge messages / newline spam) -----
  if (f.antiwall && (content.length > 1800 || content.split('\n').length >= 15)) {
    await violation(message, 'Please do not send walls of text.', 0, 'antiwall');
    return true;
  }

  // ----- Anti-Badword -----
  if (f.antibadword && cfg.badWords.length) {
    const lower = content.toLowerCase();
    if (cfg.badWords.some((w) => lower.includes(w))) {
      await violation(message, 'Watch your language.', 0, 'antibadword');
      return true;
    }
  }

  return false;
}

// ---------- Anti-Ghost-Ping ----------
client.on(Events.MessageDelete, async (message) => {
  if (!message.guild || message.partial || message.author?.bot) return;
  const cfg = getConfig(message.guild.id);
  if (!cfg.features.antighostping) return;
  if (Date.now() - message.createdTimestamp > 2 * 60 * 1000) return;

  const pinged = message.mentions.users.filter((u) => !u.bot && u.id !== message.author.id);
  const everyone = message.mentions.everyone;
  if (!pinged.size && !everyone) return;

  const embed = new EmbedBuilder()
    .setColor(ALERT)
    .setTitle('Ghost Ping Detected')
    .addFields(
      { name: 'Author', value: `${message.author}`, inline: true },
      { name: 'Pinged', value: everyone ? '@everyone/@here' : pinged.map((u) => `${u}`).join(', '), inline: true },
      { name: 'Message', value: (message.content || '—').slice(0, 900) }
    )
    .setFooter({ text: FOOTER })
    .setTimestamp();
  await message.channel.send({ embeds: [embed] }).catch(() => {});
  await log(message.guild, 'Ghost Ping', [
    { name: 'Author', value: `${message.author.tag}`, inline: true },
    { name: 'Channel', value: `<#${message.channel.id}>`, inline: true }
  ]);
});

// ============================================================
//  LOGGING + EDIT PROTECTION
// ============================================================
client.on(Events.MessageDelete, async (message) => {
  if (!message.guild || message.partial || !message.author || message.author.bot) return;
  if (botDeleted.delete(message.id)) return;
  if (!getConfig(message.guild.id).features.msglog) return;
  const fields = [
    { name: 'Author', value: `${message.author.tag} (${message.author.id})`, inline: true },
    { name: 'Channel', value: `<#${message.channel.id}>`, inline: true },
    { name: 'Content', value: clip(message.content) }
  ];
  if (message.attachments.size) fields.push({ name: 'Files', value: clip(message.attachments.map((a) => a.name).join(', ')) });
  await log(message.guild, 'Message Deleted', fields);
});

// Edited messages are logged AND scanned again (stops "post clean, edit in a scam link")
client.on(Events.MessageUpdate, async (oldMsg, newMsg) => {
  try {
    if (!newMsg.guild || !newMsg.author || newMsg.author.bot) return;
    if (oldMsg.content === newMsg.content) return;
    const cfg = getConfig(newMsg.guild.id);

    if (cfg.features.msglog && oldMsg.content != null) {
      await log(newMsg.guild, 'Message Edited', [
        { name: 'Author', value: `${newMsg.author.tag} (${newMsg.author.id})`, inline: true },
        { name: 'Channel', value: `<#${newMsg.channel.id}>`, inline: true },
        { name: 'Before', value: clip(oldMsg.content, 500) },
        { name: 'After', value: clip(newMsg.content, 500) }
      ]);
    }

    if (!newMsg.member) await newMsg.guild.members.fetch(newMsg.author.id).catch(() => {});
    if (!newMsg.member || isAutoModExempt(newMsg.member) || isBypassed(newMsg)) return;
    await runAutoMod(newMsg, true);
  } catch (e) {
    console.error('Edit scan error:', e.message);
  }
});

client.on(Events.GuildMemberAdd, async (member) => {
  if (!getConfig(member.guild.id).features.joinlog) return;
  const ageDays = (Date.now() - member.user.createdTimestamp) / 86400000;
  await log(
    member.guild,
    member.user.bot ? 'Bot Joined' : 'Member Joined',
    [
      { name: 'User', value: `${member.user.tag} (${member.id})`, inline: true },
      { name: 'Account age', value: `${ageDays.toFixed(1)} day(s)${ageDays < 7 ? ' (new account)' : ''}`, inline: true }
    ],
    COLOR
  );
});

client.on(Events.GuildMemberRemove, async (member) => {
  if (!getConfig(member.guild.id).features.joinlog) return;
  await log(member.guild, 'Member Left', [
    { name: 'User', value: `${member.user?.tag || 'Unknown'} (${member.id})` }
  ], COLOR);
});

client.on(Events.GuildBanAdd, async (ban) => {
  if (!getConfig(ban.guild.id).features.modlog) return;
  await log(ban.guild, 'Member Banned', [
    { name: 'User', value: `${ban.user.tag} (${ban.user.id})`, inline: true },
    { name: 'Reason', value: clip(ban.reason, 300), inline: true }
  ]);
});

client.on(Events.GuildBanRemove, async (ban) => {
  if (!getConfig(ban.guild.id).features.modlog) return;
  await log(ban.guild, 'Member Unbanned', [{ name: 'User', value: `${ban.user.tag} (${ban.user.id})` }], COLOR);
});

client.on(Events.GuildMemberUpdate, async (oldM, newM) => {
  if (!getConfig(newM.guild.id).features.modlog) return;
  if (oldM.communicationDisabledUntilTimestamp === newM.communicationDisabledUntilTimestamp) return;
  const until = newM.communicationDisabledUntilTimestamp;
  const active = until && until > Date.now();
  await log(
    newM.guild,
    active ? 'Member Timed Out' : 'Timeout Removed',
    [
      { name: 'User', value: `${newM.user.tag} (${newM.id})`, inline: true },
      ...(active ? [{ name: 'Until', value: `<t:${Math.floor(until / 1000)}:R>`, inline: true }] : [])
    ],
    COLOR
  );
});

client.on(Events.ChannelCreate, async (c) => {
  if (!c.guild || !getConfig(c.guild.id).features.modlog) return;
  await log(c.guild, 'Channel Created', [{ name: 'Channel', value: `#${c.name} (${c.id})` }], COLOR);
});
client.on(Events.ChannelDelete, async (c) => {
  if (!c.guild || !getConfig(c.guild.id).features.modlog) return;
  await log(c.guild, 'Channel Deleted', [{ name: 'Channel', value: `#${c.name} (${c.id})` }]);
});
client.on(Events.GuildRoleCreate, async (r) => {
  if (!getConfig(r.guild.id).features.modlog) return;
  await log(r.guild, 'Role Created', [{ name: 'Role', value: `${r.name} (${r.id})` }], COLOR);
});
client.on(Events.GuildRoleDelete, async (r) => {
  if (!getConfig(r.guild.id).features.modlog) return;
  await log(r.guild, 'Role Deleted', [{ name: 'Role', value: `${r.name} (${r.id})` }]);
});

// ============================================================
//  VERIFICATION (button + math captcha)
// ============================================================
const captchas = new Map(); // "guildId:userId" -> { answer, expires }

client.on(Events.InteractionCreate, async (interaction) => {
  try {
    if (!interaction.guild) return;
    const cfg = getConfig(interaction.guild.id);

    if (interaction.isButton() && interaction.customId === 'dmc_verify') {
      if (!cfg.verifyRole) {
        return interaction.reply({ embeds: [box('Verification is not set up.')], flags: MessageFlags.Ephemeral });
      }
      if (interaction.member.roles.cache.has(cfg.verifyRole)) {
        return interaction.reply({ embeds: [box('You are already verified.')], flags: MessageFlags.Ephemeral });
      }
      const a = Math.floor(Math.random() * 9) + 1;
      const b = Math.floor(Math.random() * 9) + 1;
      captchas.set(`${interaction.guild.id}:${interaction.user.id}`, { answer: a + b, expires: Date.now() + CAPTCHA_TTL });

      const modal = new ModalBuilder()
        .setCustomId('dmc_verify_modal')
        .setTitle('Verification')
        .addComponents(
          new ActionRowBuilder().addComponents(
            new TextInputBuilder()
              .setCustomId('answer')
              .setLabel(`What is ${a} + ${b} ?`)
              .setStyle(TextInputStyle.Short)
              .setRequired(true)
              .setMaxLength(3)
          )
        );
      return interaction.showModal(modal);
    }

    if (interaction.isModalSubmit() && interaction.customId === 'dmc_verify_modal') {
      const key = `${interaction.guild.id}:${interaction.user.id}`;
      const entry = captchas.get(key);
      captchas.delete(key);
      const given = parseInt(interaction.fields.getTextInputValue('answer'));

      if (!entry || entry.expires < Date.now() || given !== entry.answer) {
        return interaction.reply({ embeds: [box('Wrong or expired answer. Press **Verify** and try again.')], flags: MessageFlags.Ephemeral });
      }
      await interaction.member.roles.add(cfg.verifyRole, 'Verified via captcha');
      await interaction.reply({ embeds: [box('You are now verified. Welcome!')], flags: MessageFlags.Ephemeral });
      await log(interaction.guild, 'Member Verified', [{ name: 'User', value: `${interaction.user.tag}` }], COLOR);
    }
  } catch (e) {
    console.error('Interaction error:', e.message);
    // Never leave the user with "This interaction failed"
    if ((interaction.isButton() || interaction.isModalSubmit()) && !interaction.replied && !interaction.deferred) {
      await interaction
        .reply({ embeds: [box('Verification failed. Please contact a server administrator.')], flags: MessageFlags.Ephemeral })
        .catch(() => {});
    }
  }
});

// ============================================================
//  COMMANDS
//  Every handler receives { message, args, cfg } and answers with
//  the styled helpers: success() / failure() / info() / usage().
// ============================================================
const commands = Object.create(null); // no prototype => '-constructor' etc. can never match

async function lockAll(guild, lock) {
  const channels = guild.channels.cache.filter((c) => c.type === ChannelType.GuildText);
  let n = 0;
  for (const [, c] of channels) {
    await c.permissionOverwrites
      .edit(guild.roles.everyone, { SendMessages: lock ? false : null })
      .then(() => n++)
      .catch(() => {});
  }
  return n;
}

const GROUPS = [
  ['AutoMod', ['antilink', 'antiinvite', 'antiscam', 'antishortener', 'antifile', 'antispam', 'antiduplicate', 'antimention', 'anticaps', 'antiemoji', 'antizalgo', 'antiwall', 'antibadword', 'antighostping']],
  ['Server Protection', ['antinuke', 'antibot', 'antiraid', 'antinoavatar']],
  ['Logging', ['msglog', 'joinlog', 'modlog']]
];

// ---------- SECURITY PANEL ----------
commands.security = async ({ message, cfg }) => {
  const keys = Object.keys(FEATURES);
  const active = keys.filter((k) => cfg.features[k]).length;
  const embed = emb(
    'Security Panel',
    `**${active} of ${keys.length}** protections are active.\nToggle any protection with \`/<name> on|off\`. All commands: \`/dmshelp\`.`
  );
  for (const [name, list] of GROUPS) {
    embed.addFields({ name, value: list.map((k) => `${tag(cfg.features[k])}  **${label(k)}**  ·  \`/${k}\``).join('\n') });
  }
  const bypass = [...cfg.bypassChannels.map((id) => `<#${id}>`), ...cfg.bypassRoles.map((id) => `<@&${id}>`)].join(', ');
  embed.addFields(
    { name: 'Log channel', value: cfg.logChannel ? `<#${cfg.logChannel}>` : 'Not set — `/setlog`', inline: true },
    { name: 'Min account age', value: cfg.minAccountAgeDays ? `${cfg.minAccountAgeDays} day(s)` : 'Off', inline: true },
    { name: 'Nuke punishment', value: cfg.punishment, inline: true },
    { name: 'Verify role', value: cfg.verifyRole ? `<@&${cfg.verifyRole}>` : 'Not set', inline: true },
    { name: 'Allowed bots', value: cfg.allowedBots.length ? cfg.allowedBots.map((id) => `\`${id}\``).join(', ') : 'None', inline: true },
    { name: 'Whitelist', value: cfg.whitelist.length ? cfg.whitelist.map((id) => `<@${id}>`).join(', ').slice(0, 1000) : 'None', inline: true },
    { name: 'Bypass', value: bypass.slice(0, 1000) || 'None', inline: true }
  );
  if (cfg.panicSnapshot) embed.addFields({ name: 'Panic mode', value: 'Active — `/panic off` restores your previous settings.' });
  await message.reply({ embeds: [embed] });
};

// ---------- PROTECTION TOGGLES (/antilink on|off ...) ----------
for (const feature of Object.keys(FEATURES)) {
  commands[feature] = async ({ message, args, cfg }) => {
    const v = (args[0] || '').toLowerCase();
    if (v !== 'on' && v !== 'off') {
      return message.reply(
        info(label(feature), FEATURES[feature][0], [
          { name: 'Status', value: `**${cfg.features[feature] ? 'ON' : 'OFF'}**`, inline: true },
          { name: 'Change', value: `\`/${feature} on\` · \`/${feature} off\``, inline: true }
        ])
      );
    }
    const on = v === 'on';
    setFeature(cfg, feature, on); // saved to disk immediately
    await message.reply(
      success(`${label(feature)} ${on ? 'enabled' : 'disabled'}`, FEATURES[feature][0], [
        { name: 'Status', value: `**${on ? 'ON' : 'OFF'}**`, inline: true },
        { name: 'Changed by', value: `${message.author}`, inline: true }
      ])
    );
    await log(message.guild, 'Protection Changed', [
      { name: 'Protection', value: label(feature), inline: true },
      { name: 'New state', value: on ? 'ON' : 'OFF', inline: true },
      { name: 'By', value: message.author.tag, inline: true }
    ], COLOR);
  };
}

// ---------- ANTI NEW ACCOUNT ----------
commands.antinew = async ({ message, args, cfg }) => {
  const v = (args[0] || '').toLowerCase();
  if (v === 'off') {
    cfg.minAccountAgeDays = 0;
    flushSave();
    return message.reply(success('Anti-New-Account disabled', 'Accounts of any age can join.'));
  }
  const days = parseInt(v);
  if (!days || days < 1 || days > 365) return message.reply(usage('/antinew <days|off>', '/antinew 7'));
  cfg.minAccountAgeDays = days;
  flushSave();
  await message.reply(success('Anti-New-Account enabled', `Accounts younger than **${days} day(s)** are kicked on join.`));
};

// ---------- LOG CHANNEL ----------
commands.setlog = async ({ message, cfg }) => {
  const ch = message.mentions.channels.first() || message.channel;
  cfg.logChannel = ch.id;
  flushSave();
  await message.reply(success('Log channel set', `Security logs will be sent to <#${ch.id}>.`));
};

// ---------- WHITELIST ----------
commands.whitelist = async ({ message, args, cfg }) => {
  const sub = (args[0] || '').toLowerCase();
  if (sub === 'list') {
    return message.reply(
      info('Whitelist', cfg.whitelist.length ? cfg.whitelist.map((id) => `<@${id}>`).join('\n').slice(0, 4000) : 'The whitelist is empty.')
    );
  }
  if (sub !== 'add' && sub !== 'remove') return message.reply(usage('/whitelist add|remove|list [user]', '/whitelist add @user'));
  const member = await getMember(message, args[1]);
  if (!member) return message.reply(failure('Mention a user (or give an ID).', 'User not found'));

  if (sub === 'add') {
    if (!cfg.whitelist.includes(member.id)) cfg.whitelist.push(member.id);
    flushSave();
    await message.reply(success('User whitelisted', `**${member.user.tag}** now bypasses AutoMod and Anti-Nuke.`));
  } else {
    cfg.whitelist = cfg.whitelist.filter((id) => id !== member.id);
    flushSave();
    await message.reply(success('User removed from whitelist', `**${member.user.tag}** is protected by AutoMod rules again.`));
  }
};

// ---------- BYPASS (channels / roles ignored by AutoMod) ----------
commands.bypass = async ({ message, args, cfg }) => {
  const sub = (args[0] || '').toLowerCase();
  if (sub === 'list') {
    const all = [...cfg.bypassChannels.map((id) => `<#${id}>`), ...cfg.bypassRoles.map((id) => `<@&${id}>`)];
    return message.reply(info('AutoMod Bypass', all.length ? all.join('\n').slice(0, 4000) : 'No bypass set.'));
  }
  const ch = message.mentions.channels.first();
  const role = message.mentions.roles.first();
  if ((sub !== 'add' && sub !== 'remove') || (!ch && !role)) {
    return message.reply(usage('/bypass add|remove|list [channel] [role]', '/bypass add channel:#staff'));
  }
  const [list, id] = ch ? [cfg.bypassChannels, ch.id] : [cfg.bypassRoles, role.id];
  const updated = sub === 'add' ? (list.includes(id) ? list : [...list, id]) : list.filter((x) => x !== id);
  if (ch) cfg.bypassChannels = updated;
  else cfg.bypassRoles = updated;
  flushSave();
  await message.reply(success(`Bypass ${sub === 'add' ? 'added' : 'removed'}`, ch ? `<#${id}>` : `<@&${id}>`));
};

// ---------- BADWORDS ----------
commands.badword = async ({ message, args, cfg }) => {
  const sub = (args[0] || '').toLowerCase();
  const word = args.slice(1).join(' ').toLowerCase();
  if (sub === 'list') {
    return message.reply(
      info('Bad Words', cfg.badWords.length ? cfg.badWords.map((w) => `\`${w}\``).join(', ').slice(0, 4000) : 'No bad words set.')
    );
  }
  if ((sub !== 'add' && sub !== 'remove') || !word) return message.reply(usage('/badword add|remove|list [word]', '/badword add example'));
  if (sub === 'add') {
    if (!cfg.badWords.includes(word)) cfg.badWords.push(word);
    flushSave();
    await message.reply(success('Bad word added', `Added \`${word}\`. Make sure it is active: \`/antibadword on\``));
  } else {
    cfg.badWords = cfg.badWords.filter((w) => w !== word);
    flushSave();
    await message.reply(success('Bad word removed', `Removed \`${word}\`.`));
  }
  message.delete().catch(() => {});
};

// ---------- ALLOWED DOMAINS (for Anti-Link) ----------
commands.allowlink = async ({ message, args, cfg }) => {
  const sub = (args[0] || '').toLowerCase();
  const domain = (args[1] || '').toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '');
  if (sub === 'list') {
    return message.reply(
      info('Allowed Domains', cfg.allowedDomains.length ? cfg.allowedDomains.map((d) => `\`${d}\``).join(', ').slice(0, 4000) : 'No allowed domains.')
    );
  }
  if ((sub !== 'add' && sub !== 'remove') || !domain) return message.reply(usage('/allowlink add|remove|list [domain]', '/allowlink add youtube.com'));
  if (sub === 'add') {
    if (!cfg.allowedDomains.includes(domain)) cfg.allowedDomains.push(domain);
    flushSave();
    await message.reply(success('Domain allowed', `\`${domain}\` is allowed even when Anti-Link is ON.`));
  } else {
    cfg.allowedDomains = cfg.allowedDomains.filter((d) => d !== domain);
    flushSave();
    await message.reply(success('Domain removed', `\`${domain}\` is no longer allowed.`));
  }
};

// ---------- NUKE PUNISHMENT ----------
commands.punishment = async ({ message, args, cfg }) => {
  const v = (args[0] || '').toLowerCase();
  if (v !== 'ban' && v !== 'kick') return message.reply(usage('/punishment ban|kick', '/punishment ban'));
  cfg.punishment = v;
  flushSave();
  await message.reply(success('Punishment updated', `Anti-Nuke and Anti-Bot offenders will be **${v === 'ban' ? 'banned' : 'kicked'}**.`));
};

// ---------- LOCK / UNLOCK ----------
commands.lock = async ({ message }) => {
  await message.channel.permissionOverwrites.edit(message.guild.roles.everyone, { SendMessages: false });
  await message.reply(success('Channel locked', `<#${message.channel.id}> is now read-only for @everyone.`));
};
commands.unlock = async ({ message }) => {
  await message.channel.permissionOverwrites.edit(message.guild.roles.everyone, { SendMessages: null });
  await message.reply(success('Channel unlocked', `<#${message.channel.id}> is open again.`));
};

// ---------- LOCKDOWN ----------
commands.lockdown = async ({ message }) => {
  const n = await lockAll(message.guild, true);
  await message.reply(success('Server lockdown active', `**${n}** text channels locked. Use \`/unlockdown\` to undo.`));
  await log(message.guild, 'Server Lockdown', [{ name: 'By', value: message.author.tag }]);
};
commands.unlockdown = async ({ message }) => {
  const n = await lockAll(message.guild, false);
  await message.reply(success('Lockdown lifted', `**${n}** text channels unlocked.`));
  await log(message.guild, 'Lockdown Lifted', [{ name: 'By', value: message.author.tag }], COLOR);
};

// ---------- PANIC MODE ----------
// Turns every protection on for the emergency and remembers your previous
// settings, so "/panic off" puts everything back exactly as you had it.
commands.panic = async ({ message, args, cfg }) => {
  const v = (args[0] || 'on').toLowerCase();
  if (v === 'off') {
    raidUntil.delete(message.guild.id);
    let restored = 0;
    if (cfg.panicSnapshot) {
      for (const [k, val] of Object.entries(cfg.panicSnapshot)) {
        if (k in FEATURES) {
          cfg.features[k] = !!val;
          restored++;
        }
      }
      cfg.panicSnapshot = null;
      flushSave();
    }
    const n = await lockAll(message.guild, false);
    await message.reply(
      success('Panic mode off', 'Raid mode cleared and channels unlocked.', [
        { name: 'Channels unlocked', value: `${n}`, inline: true },
        { name: 'Protections restored', value: `${restored}`, inline: true }
      ])
    );
    return log(message.guild, 'Panic Mode Ended', [{ name: 'By', value: message.author.tag }], COLOR);
  }
  if (!cfg.panicSnapshot) cfg.panicSnapshot = { ...cfg.features };
  for (const k of Object.keys(FEATURES)) cfg.features[k] = true;
  flushSave();
  raidUntil.set(message.guild.id, Date.now() + 10 * 60 * 1000);
  const n = await lockAll(message.guild, true);
  await message.reply(
    info('Panic mode enabled', 'Maximum protection is active.', [
      { name: 'Protections', value: 'All enabled', inline: true },
      { name: 'Channels locked', value: `${n}`, inline: true },
      { name: 'New joins', value: 'Kicked for 10 minutes', inline: true },
      { name: 'End panic mode', value: '`/panic off` — your previous settings are restored.' }
    ])
  );
  await log(message.guild, 'Panic Mode Enabled', [{ name: 'By', value: message.author.tag }]);
};

// ---------- VERIFICATION ----------
commands.setverify = async ({ message, cfg }) => {
  const role = message.mentions.roles.first();
  if (!role) return message.reply(usage('/setverify <role>', '/setverify role:@Verified'));
  cfg.verifyRole = role.id;
  flushSave();
  await message.reply(success('Verify role set', `New members receive **${role.name}** after the captcha.\nNext: run \`/verifypanel\` in your verify channel.`));
};
commands.verifypanel = async ({ message, cfg }) => {
  if (!cfg.verifyRole) return message.reply(failure('Set a role first: `/setverify`', 'Verification not set up'));
  const embed = emb('Verification', 'Press the button below and solve the captcha to get access to the server.');
  const row = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('dmc_verify').setLabel('Verify').setStyle(ButtonStyle.Success)
  );
  await message.channel.send({ embeds: [embed], components: [row] });
  message.delete().catch(() => {});
};

// ============================================================
//  MODERATION + SERVER TOOLS
// ============================================================
/** "10s" / "5m" / "2h" / "1d" -> milliseconds (1 second to 28 days), or null when invalid. */
function parseDuration(str) {
  const m = /^(\d+)(s|m|h|d)$/i.exec(str || '');
  if (!m) return null;
  const ms = parseInt(m[1]) * { s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2].toLowerCase()];
  return ms >= 1000 && ms <= 28 * 86400000 ? ms : null;
}

/** Returns an error text if the moderator may not act on this member, otherwise null. */
function hierarchyError(message, target) {
  const me = message.guild.members.me;
  if (target.id === message.author.id) return 'You cannot do this to yourself.';
  if (target.id === message.guild.ownerId) return 'You cannot do this to the server owner.';
  if (target.id === client.user.id) return 'You cannot do this to me.';
  if (message.author.id !== message.guild.ownerId && target.roles.highest.position >= message.member.roles.highest.position) {
    return 'That user has an equal or higher role than you.';
  }
  if (target.roles.highest.position >= me.roles.highest.position) {
    return 'That user has an equal or higher role than me. Move my role higher.';
  }
  return null;
}

/** Standard fields for a moderation result card. */
const modFields = (user, message, reason, extra = []) => [
  { name: 'User', value: `${user} (${user.tag})`, inline: true },
  { name: 'Moderator', value: `${message.author}`, inline: true },
  ...extra,
  { name: 'Reason', value: clip(reason, 500) }
];

commands.ban = async ({ message, args }) => {
  const member = await getMember(message, args[0]);
  const idArg = /^\d{15,25}$/.test(args[0] || '') ? args[0] : null;
  const reason = args.slice(1).join(' ') || 'No reason provided';
  if (!member && !idArg) return message.reply(usage('/ban <user> [reason]', '/ban user:@Name reason:Advertising'));
  if (member) {
    const err = hierarchyError(message, member);
    if (err) return message.reply(failure(err, 'Not allowed'));
    if (!member.bannable) return message.reply(failure('I cannot ban that user (my role is too low).', 'Not allowed'));
    // DM first: a user cannot be messaged after the ban
    await sendDM(member.user, 'You have been banned', [
      { name: 'Server', value: message.guild.name },
      { name: 'Reason', value: clip(reason, 500) }
    ]);
  } else if ([message.author.id, message.guild.ownerId, client.user.id].includes(idArg)) {
    return message.reply(failure('You cannot ban that user.', 'Not allowed'));
  }
  const id = member ? member.id : idArg;
  await message.guild.members.ban(id, { reason: `${message.author.tag}: ${reason}` });
  const user = member ? member.user : await client.users.fetch(id).catch(() => ({ id, tag: 'Unknown user', toString: () => `<@${id}>` }));
  await message.reply(success('Member banned', null, modFields(user, message, reason)));
};

commands.unban = async ({ message, args }) => {
  if (!/^\d{15,25}$/.test(args[0] || '')) return message.reply(usage('/unban <user_id>', '/unban user_id:123456789012345678'));
  try {
    await message.guild.members.unban(args[0], `Unbanned by ${message.author.tag}`);
  } catch (e) {
    return message.reply(failure('That user is not banned (or the ID is wrong).', 'Unban failed'));
  }
  await message.reply(success('Member unbanned', null, [
    { name: 'User', value: `<@${args[0]}>`, inline: true },
    { name: 'Moderator', value: `${message.author}`, inline: true }
  ]));
};

commands.kick = async ({ message, args }) => {
  const member = await getMember(message, args[0]);
  if (!member) return message.reply(usage('/kick <user> [reason]', '/kick user:@Name reason:Breaking rules'));
  const err = hierarchyError(message, member);
  if (err) return message.reply(failure(err, 'Not allowed'));
  if (!member.kickable) return message.reply(failure('I cannot kick that user (my role is too low).', 'Not allowed'));
  const reason = args.slice(1).join(' ') || 'No reason provided';
  await sendDM(member.user, 'You have been kicked', [
    { name: 'Server', value: message.guild.name },
    { name: 'Reason', value: clip(reason, 500) }
  ]);
  await member.kick(`${message.author.tag}: ${reason}`);
  await message.reply(success('Member kicked', null, modFields(member.user, message, reason)));
};

commands.mute = async ({ message, args }) => {
  const member = await getMember(message, args[0]);
  const ms = parseDuration(args[1]);
  if (!member || !ms) return message.reply(usage('/mute <user> <time> [reason]', '/mute user:@Name time:10m reason:Spam  (max 28d)'));
  const err = hierarchyError(message, member);
  if (err) return message.reply(failure(err, 'Not allowed'));
  if (!member.moderatable) return message.reply(failure('I cannot mute that user (my role is too low).', 'Not allowed'));
  const reason = args.slice(2).join(' ') || 'No reason provided';
  await member.timeout(ms, `${message.author.tag}: ${reason}`);
  await sendDM(member.user, 'You have been muted', [
    { name: 'Server', value: message.guild.name },
    { name: 'Duration', value: args[1] },
    { name: 'Reason', value: clip(reason, 500) }
  ]);
  const until = Math.floor((Date.now() + ms) / 1000);
  await message.reply(
    success('Member muted', null, modFields(member.user, message, reason, [
      { name: 'Duration', value: `${args[1]} (ends <t:${until}:R>)`, inline: true }
    ]))
  );
};
commands.timeout = commands.mute;

commands.unmute = async ({ message, args }) => {
  const member = await getMember(message, args[0]);
  if (!member) return message.reply(usage('/unmute <user>', '/unmute user:@Name'));
  if (!member.moderatable) return message.reply(failure('I cannot unmute that user.', 'Not allowed'));
  await member.timeout(null, `Unmuted by ${message.author.tag}`);
  await message.reply(success('Member unmuted', null, [
    { name: 'User', value: `${member.user} (${member.user.tag})`, inline: true },
    { name: 'Moderator', value: `${message.author}`, inline: true }
  ]));
};

// ---------- WARNINGS (3 = 1h timeout, 5 = punishment) ----------
commands.warn = async ({ message, args, cfg }) => {
  const member = await getMember(message, args[0]);
  if (!member) return message.reply(usage('/warn <user> [reason]', '/warn user:@Name reason:Toxic behaviour'));
  const err = hierarchyError(message, member);
  if (err) return message.reply(failure(err, 'Not allowed'));
  const reason = args.slice(1).join(' ') || 'No reason provided';
  const list = cfg.warns[member.id] || (cfg.warns[member.id] = []);
  list.push({ reason: reason.slice(0, 200), by: message.author.id, t: Date.now() });
  flushSave();
  await sendDM(member.user, 'You received a warning', [
    { name: 'Server', value: message.guild.name },
    { name: 'Reason', value: clip(reason, 500) },
    { name: 'Total warnings', value: `${list.length}` }
  ]);
  let action = 'None';
  if (list.length >= 5) {
    const r = await punish(message.guild, member.id, 'Reached 5 warnings');
    action = `5 warnings reached → **${r}**`;
  } else if (list.length >= 3 && member.moderatable) {
    await member.timeout(60 * 60 * 1000, 'Reached 3 warnings').catch(() => {});
    action = '3 warnings reached → timed out for **1h**';
  }
  await message.reply(
    success('Member warned', null, modFields(member.user, message, reason, [
      { name: 'Total warnings', value: `${list.length}`, inline: true },
      { name: 'Automatic action', value: action, inline: true }
    ]))
  );
  await log(message.guild, 'Member Warned', [
    { name: 'User', value: `${member.user.tag} (${member.id})`, inline: true },
    { name: 'By', value: message.author.tag, inline: true },
    { name: 'Reason', value: clip(reason, 300) }
  ]);
};

commands.warnings = async ({ message, args, cfg }) => {
  const member = await getMember(message, args[0]);
  if (!member) return message.reply(usage('/warnings <user>', '/warnings user:@Name'));
  const list = cfg.warns[member.id] || [];
  if (!list.length) return message.reply(info('Warnings', `**${member.user.tag}** has no warnings.`));
  const shown = list.slice(-10);
  const start = list.length - shown.length;
  const lines = shown.map((w, i) => `**${start + i + 1}.** ${clip(w.reason, 120)} — <t:${Math.floor(w.t / 1000)}:R> by <@${w.by}>`);
  await message.reply(info(`Warnings — ${member.user.tag}`, lines.join('\n'), [
    { name: 'Total', value: `${list.length}`, inline: true }
  ]));
};

commands.clearwarns = async ({ message, args, cfg }) => {
  const member = await getMember(message, args[0]);
  if (!member) return message.reply(usage('/clearwarns <user>', '/clearwarns user:@Name'));
  delete cfg.warns[member.id];
  flushSave();
  await message.reply(success('Warnings cleared', `All warnings for **${member.user.tag}** were removed.`));
};

// ---------- CHANNEL TOOLS ----------
commands.purge = async ({ message, args }) => {
  const n = parseInt(args[0]);
  if (!n || n < 1 || n > 100) return message.reply(usage('/purge <1-100>', '/purge amount:20'));
  await message.delete().catch(() => {});
  const deleted = await message.channel.bulkDelete(n, true);
  const m = await message.channel.send(success('Messages purged', `Deleted **${deleted.size}** message(s).`));
  setTimeout(() => m.delete().catch(() => {}), 4000);
};

commands.slowmode = async ({ message, args }) => {
  const v = (args[0] || '').toLowerCase();
  const s = v === 'off' ? 0 : parseInt(v);
  if (isNaN(s) || s < 0 || s > 21600) return message.reply(usage('/slowmode <seconds|off>', '/slowmode seconds:10  (max 21600)'));
  await message.channel.setRateLimitPerUser(s);
  await message.reply(success(s ? 'Slowmode enabled' : 'Slowmode disabled', s ? `Members can send one message every **${s}s**.` : 'Slowmode is off.'));
};

commands.hide = async ({ message }) => {
  await message.channel.permissionOverwrites.edit(message.guild.roles.everyone, { ViewChannel: false });
  await message.reply(success('Channel hidden', `<#${message.channel.id}> is hidden from @everyone.`));
};
commands.unhide = async ({ message }) => {
  await message.channel.permissionOverwrites.edit(message.guild.roles.everyone, { ViewChannel: null });
  await message.reply(success('Channel visible', `<#${message.channel.id}> is visible again.`));
};

// ---------- RAID MODE (manual) ----------
commands.raidmode = async ({ message, args }) => {
  const v = (args[0] || '').toLowerCase();
  if (v === 'on') {
    raidUntil.set(message.guild.id, Date.now() + 10 * 60 * 1000);
    return message.reply(info('Raid mode enabled', 'Every new member is kicked for the next **10 minutes**.', [{ name: 'Turn off', value: '`/raidmode off`' }]));
  }
  if (v === 'off') {
    raidUntil.delete(message.guild.id);
    return message.reply(success('Raid mode off', 'New members can join normally.'));
  }
  const left = (raidUntil.get(message.guild.id) || 0) - Date.now();
  await message.reply(
    info('Raid mode', left > 0 ? `Active — **${Math.ceil(left / 60000)} min** left.` : 'Currently off.', [
      { name: 'Change', value: '`/raidmode on` · `/raidmode off`' }
    ])
  );
};

// ---------- ALLOWED BOTS (Anti-Bot exceptions) ----------
commands.botallow = async ({ message, args, cfg }) => {
  const sub = (args[0] || '').toLowerCase();
  const id = args[1];
  if (sub === 'list') {
    return message.reply(info('Allowed Bots', cfg.allowedBots.length ? cfg.allowedBots.map((b) => `<@${b}> (\`${b}\`)`).join('\n') : 'No allowed bots.'));
  }
  if ((sub !== 'add' && sub !== 'remove') || !/^\d{15,25}$/.test(id || '')) {
    return message.reply(usage('/botallow add|remove|list [bot_id]', '/botallow add bot_id:123456789012345678'));
  }
  cfg.allowedBots = sub === 'add' ? [...new Set([...cfg.allowedBots, id])] : cfg.allowedBots.filter((b) => b !== id);
  flushSave();
  await message.reply(success(
    sub === 'add' ? 'Bot allowed' : 'Bot removed',
    sub === 'add' ? `\`${id}\` can be added without being kicked.` : `\`${id}\` was removed from the allowed list.`
  ));
};

// ---------- SERVER VERIFICATION LEVEL ----------
commands.verifylevel = async ({ message, args }) => {
  const map = {
    low: GuildVerificationLevel.Low,
    medium: GuildVerificationLevel.Medium,
    high: GuildVerificationLevel.High,
    highest: GuildVerificationLevel.VeryHigh
  };
  const v = (args[0] || '').toLowerCase();
  if (!(v in map)) return message.reply(usage('/verifylevel low|medium|high|highest', '/verifylevel level:high'));
  await message.guild.setVerificationLevel(map[v], `Set by ${message.author.tag}`);
  await message.reply(success('Verification level updated', `The server verification level is now **${v}**.`));
};

// ---------- USER INFO ----------
commands.userinfo = async ({ message, args, cfg }) => {
  const member = (await getMember(message, args[0])) || message.member;
  const u = member.user;
  const ageDays = (Date.now() - u.createdTimestamp) / 86400000;
  const risky = DANGEROUS_PERMS.some((p) => member.permissions.has(p));
  const embed = emb(`${u.tag}`, `${u} · \`${u.id}\``, [
    { name: 'Account created', value: `<t:${Math.floor(u.createdTimestamp / 1000)}:R>${ageDays < 7 ? ' (new account)' : ''}`, inline: true },
    { name: 'Joined server', value: member.joinedTimestamp ? `<t:${Math.floor(member.joinedTimestamp / 1000)}:R>` : 'Unknown', inline: true },
    { name: 'Roles', value: `${member.roles.cache.size - 1}`, inline: true },
    { name: 'Warnings', value: `${(cfg.warns[u.id] || []).length}`, inline: true },
    { name: 'Dangerous perms', value: risky ? 'Yes' : 'No', inline: true },
    { name: 'Custom avatar', value: u.avatar ? 'Yes' : 'No', inline: true },
    { name: 'Whitelisted', value: cfg.whitelist.includes(u.id) ? 'Yes' : 'No', inline: true },
    { name: 'Bot', value: u.bot ? 'Yes' : 'No', inline: true }
  ]).setThumbnail(u.displayAvatarURL());
  await message.reply({ embeds: [embed] });
};

// ---------- SECURITY AUDIT ----------
commands.audit = async ({ message, cfg }) => {
  const g = message.guild;
  const me = g.members.me;
  const passed = [];
  const issues = [];
  const check = (cond, good, warn) => (cond ? passed : issues).push(`• ${cond ? good : warn}`);

  check(g.mfaLevel === 1, '2FA is required for moderators', '2FA is **not** required for moderators (Server Settings → Safety Setup)');
  check(g.verificationLevel >= GuildVerificationLevel.Medium, 'Verification level is Medium or higher', 'Verification level is low → `/verifylevel high`');
  check(g.explicitContentFilter === GuildExplicitContentFilter.AllMembers, 'Media scan is on for all members', 'Media scan is not on for all members → `/harden`');

  const need = {
    BanMembers: 'Ban Members',
    KickMembers: 'Kick Members',
    ManageRoles: 'Manage Roles',
    ManageChannels: 'Manage Channels',
    ModerateMembers: 'Timeout Members',
    ViewAuditLog: 'View Audit Log',
    ManageMessages: 'Manage Messages',
    ManageWebhooks: 'Manage Webhooks'
  };
  const missing = Object.entries(need).filter(([k]) => !me.permissions.has(PermissionFlagsBits[k])).map(([, n]) => n);
  check(!missing.length, 'I have every permission I need', `I am missing: ${missing.join(', ')}`);
  check(me.roles.highest.position >= g.roles.highest.position, 'My role is at the top', 'My role is **not** at the top. Move it above all other roles');

  const evPerms = [
    ['Administrator', 'Administrator'], ['ManageGuild', 'Manage Server'], ['ManageRoles', 'Manage Roles'],
    ['ManageChannels', 'Manage Channels'], ['ManageWebhooks', 'Manage Webhooks'], ['KickMembers', 'Kick'],
    ['BanMembers', 'Ban'], ['MentionEveryone', 'Mention @everyone'], ['ManageMessages', 'Manage Messages']
  ];
  const evBad = evPerms.filter(([k]) => g.roles.everyone.permissions.has(PermissionFlagsBits[k])).map(([, n]) => n);
  check(!evBad.length, '@everyone has no dangerous permissions', `@everyone has: ${evBad.join(', ')} → \`/harden\``);

  const adminRoles = g.roles.cache.filter((r) => !r.managed && r.id !== g.id && r.permissions.has(PermissionFlagsBits.Administrator));
  check(adminRoles.size <= 2, `Only ${adminRoles.size} admin role(s)`, `${adminRoles.size} roles have Administrator: ${adminRoles.map((r) => r.name).join(', ').slice(0, 300)}`);

  await g.members.fetch().catch(() => {});
  const adminBots = g.members.cache.filter((m) => m.user.bot && m.id !== client.user.id && m.permissions.has(PermissionFlagsBits.Administrator));
  check(!adminBots.size, 'No other bot has Administrator', `Bots with Administrator: ${adminBots.map((m) => m.user.tag).join(', ').slice(0, 300)}`);

  check(!!cfg.logChannel, 'Log channel is set', 'No log channel → `/setlog`');
  check(cfg.minAccountAgeDays > 0, `Anti-New-Account is ON (${cfg.minAccountAgeDays}d)`, 'Anti-New-Account is OFF → `/antinew 7`');
  const off = Object.keys(FEATURES).filter((k) => FEATURES[k][1] && !cfg.features[k]);
  check(!off.length, 'All recommended protections are ON', `Recommended protections OFF: ${off.map(label).join(', ')}`);

  const total = passed.length + issues.length;
  const embed = emb(`Security Audit — ${passed.length}/${total} passed`, issues.length ? `**${issues.length}** item(s) need attention.` : 'Everything looks good.');
  if (issues.length) embed.addFields({ name: 'Needs attention', value: issues.join('\n').slice(0, 1024) });
  if (passed.length) embed.addFields({ name: 'Passed', value: passed.join('\n').slice(0, 1024) });
  await message.reply({ embeds: [embed] });
};

// ---------- ONE-CLICK HARDENING ----------
// Never overrides a protection you switched on/off yourself.
commands.harden = async ({ message, cfg }) => {
  const g = message.guild;
  const done = [];
  try {
    await g.setVerificationLevel(GuildVerificationLevel.High, 'Harden');
    done.push('Verification level → High');
  } catch (e) {}
  try {
    await g.setExplicitContentFilter(GuildExplicitContentFilter.AllMembers, 'Harden');
    done.push('Media scan → all members');
  } catch (e) {}
  try {
    const ev = g.roles.everyone;
    const strip = [
      PermissionFlagsBits.Administrator, PermissionFlagsBits.ManageGuild, PermissionFlagsBits.ManageRoles,
      PermissionFlagsBits.ManageChannels, PermissionFlagsBits.ManageWebhooks, PermissionFlagsBits.KickMembers,
      PermissionFlagsBits.BanMembers, PermissionFlagsBits.MentionEveryone, PermissionFlagsBits.ManageMessages
    ];
    const after = ev.permissions.remove(strip);
    if (after.bitfield !== ev.permissions.bitfield) {
      await ev.setPermissions(after, 'Harden');
      done.push('Removed dangerous permissions from @everyone');
    }
  } catch (e) {}
  const skipped = [];
  for (const [k, [, def]] of Object.entries(FEATURES)) {
    if (!def) continue;
    if (cfg.touched[k]) {
      if (!cfg.features[k]) skipped.push(label(k));
      continue;
    }
    cfg.features[k] = true;
  }
  flushSave();
  done.push('Recommended protections → ON');
  const embed = success('Server hardened', null, [
    { name: 'Applied', value: done.map((d) => `• ${d}`).join('\n') }
  ]);
  if (skipped.length) {
    embed.embeds[0].addFields({ name: 'Skipped (you turned them off)', value: skipped.join(', ') });
  }
  await message.reply(embed);
  await log(g, 'Server Hardened', [{ name: 'By', value: message.author.tag }], COLOR);
};

// ---------- HELP ----------
commands.dmshelp = async ({ message }) => {
  const embed = emb(
    'Tome Security — Command Guide',
    'Only **Administrators** can use these commands.\n`/security` shows the live panel · `/audit` runs a security check-up.',
    [
      {
        name: 'Protections  (`on` / `off`)',
        value: GROUPS.map(([name, list]) => `**${name}:** ${list.map((k) => `\`/${k}\``).join(' ')}`).join('\n').slice(0, 1024)
      },
      {
        name: 'Settings',
        value: [
          '`/antinew <days|off>` — Kick accounts younger than X days',
          '`/badword add|remove|list` — Bad word list',
          '`/allowlink add|remove|list` — Domains allowed by Anti-Link',
          '`/whitelist add|remove|list` — Users that bypass protections',
          '`/botallow add|remove|list` — Bots Anti-Bot may keep',
          '`/bypass add|remove|list` — Channels / roles AutoMod ignores',
          '`/setlog` — Security log channel',
          '`/punishment ban|kick` — Anti-Nuke punishment'
        ].join('\n')
      },
      {
        name: 'Moderation',
        value: [
          '`/ban` · `/unban` · `/kick`',
          '`/mute` · `/unmute`',
          '`/warn` · `/warnings` · `/clearwarns` (3 = 1h timeout, 5 = punishment)',
          '`/purge` · `/slowmode` · `/hide` · `/unhide`'
        ].join('\n')
      },
      {
        name: 'Server Tools',
        value: [
          '`/audit` — Security check-up',
          '`/harden` — Apply recommended hardening',
          '`/userinfo` — Account age, warnings, risky perms',
          '`/verifylevel` — Server verification level'
        ].join('\n')
      },
      {
        name: 'Messaging',
        value: ['`/dm` — Send a DM (shows who sent it)', '`/prvdm` — Send an anonymous DM'].join('\n')
      },
      {
        name: 'Emergency & Verification',
        value: [
          '`/panic on|off` — Everything on + lock server (off restores your settings)',
          '`/raidmode on|off` — Kick every new join',
          '`/lockdown` · `/unlockdown` — Lock / unlock all channels',
          '`/lock` · `/unlock` — Lock / unlock this channel',
          '`/setverify` + `/verifypanel` — Captcha verification'
        ].join('\n')
      }
    ]
  );
  await message.reply({ embeds: [embed] });
  message.delete().catch(() => {});
};

// ============================================================
//  SLASH COMMAND DEFINITIONS
// ============================================================
const ON_OFF = { choices: ['on', 'off'] };
const TEXT_CH = { types: [ChannelType.GuildText, ChannelType.GuildAnnouncement] };
const ANY_CH = { types: [ChannelType.GuildText, ChannelType.GuildAnnouncement, ChannelType.GuildCategory] };

const addUser = ['user', 'user', 'Target member', true];
const reasonOpt = ['string', 'reason', 'Reason', false];

// [name, description, options, subcommands]
// option = [type, name, description, required, extra]
const SPECS = [
  ['security', 'Show the security panel'],
  ...Object.entries(FEATURES).map(([k, [d]]) => [
    k, d.slice(0, 100), [['string', 'state', 'Turn on or off', true, ON_OFF]]
  ]),
  ['antinew', 'Kick accounts younger than X days', [['string', 'days', 'Number of days, or "off"', true]]],
  ['setlog', 'Set the security log channel', [['channel', 'channel', 'Log channel (default: this channel)', false, TEXT_CH]]],
  ['whitelist', 'Manage the whitelist', [], {
    add: ['Whitelist a user', [['user', 'user', 'Member', true]]],
    remove: ['Remove a user from whitelist', [['user', 'user', 'Member', true]]],
    list: ['Show the whitelist', []]
  }],
  ['bypass', 'Channels / roles ignored by AutoMod', [], {
    add: ['Add a bypass', [['channel', 'channel', 'Channel or category', false, ANY_CH], ['role', 'role', 'Role', false]]],
    remove: ['Remove a bypass', [['channel', 'channel', 'Channel or category', false, ANY_CH], ['role', 'role', 'Role', false]]],
    list: ['Show bypasses', []]
  }],
  ['badword', 'Manage the bad word list', [], {
    add: ['Add a bad word', [['string', 'word', 'Word', true]]],
    remove: ['Remove a bad word', [['string', 'word', 'Word', true]]],
    list: ['Show bad words', []]
  }],
  ['allowlink', 'Domains allowed when Anti-Link is ON', [], {
    add: ['Allow a domain', [['string', 'domain', 'e.g. youtube.com', true]]],
    remove: ['Remove an allowed domain', [['string', 'domain', 'e.g. youtube.com', true]]],
    list: ['Show allowed domains', []]
  }],
  ['punishment', 'Set the Anti-Nuke / Anti-Bot punishment', [['string', 'type', 'ban or kick', true, { choices: ['ban', 'kick'] }]]],
  ['lock', 'Lock this channel'],
  ['unlock', 'Unlock this channel'],
  ['lockdown', 'Lock ALL channels'],
  ['unlockdown', 'Unlock ALL channels'],
  ['panic', 'Enable everything + lock the server', [['string', 'state', 'on (default) or off', false, ON_OFF]]],
  ['setverify', 'Set the role given on verification', [['role', 'role', 'Verified role', true]]],
  ['verifypanel', 'Post the captcha verification panel here'],
  ['ban', 'Ban a member (or a user ID)', [addUser, reasonOpt]],
  ['unban', 'Unban a user by ID', [['string', 'user_id', 'User ID', true]]],
  ['kick', 'Kick a member', [addUser, reasonOpt]],
  ['mute', 'Timeout a member', [addUser, ['string', 'time', 'e.g. 10s, 5m, 2h, 1d (max 28d)', true], reasonOpt]],
  ['unmute', 'Remove a timeout', [addUser]],
  ['warn', 'Warn a member (3 = 1h timeout, 5 = punishment)', [addUser, reasonOpt]],
  ['warnings', "Show a member's warnings", [addUser]],
  ['clearwarns', "Clear a member's warnings", [addUser]],
  ['purge', 'Delete messages (1-100)', [['int', 'amount', 'Number of messages', true, { min: 1, max: 100 }]]],
  ['slowmode', 'Set slowmode in this channel', [['string', 'seconds', 'Seconds (0-21600) or off', true]]],
  ['hide', 'Hide this channel from @everyone'],
  ['unhide', 'Make this channel visible again'],
  ['raidmode', 'Kick every new join for 10 minutes', [['string', 'state', 'on or off', false, ON_OFF]]],
  ['botallow', 'Bots Anti-Bot may keep', [], {
    add: ['Allow a bot', [['string', 'bot_id', 'Bot ID', true]]],
    remove: ['Disallow a bot', [['string', 'bot_id', 'Bot ID', true]]],
    list: ['Show allowed bots', []]
  }],
  ['verifylevel', 'Set the server verification level', [['string', 'level', 'Level', true, { choices: ['low', 'medium', 'high', 'highest'] }]]],
  ['userinfo', 'Account age, warns, risky perms', [['user', 'user', 'Member (default: you)', false]]],
  ['audit', 'Run a security check-up'],
  ['harden', 'Apply recommended server hardening'],
  ['dmshelp', 'Show all security commands'],
  ['dm', 'Send a DM (shows who sent it)', [['user', 'user', 'Member to DM', true], ['string', 'message', 'Message', true]]],
  ['prvdm', 'Send an anonymous DM (sender hidden)', [['user', 'user', 'Member to DM', true], ['string', 'message', 'Message', true]]]
];

function addOpt(builder, [type, name, desc, req, extra = {}]) {
  const method = { user: 'addUserOption', string: 'addStringOption', int: 'addIntegerOption', channel: 'addChannelOption', role: 'addRoleOption' }[type];
  return builder[method]((o) => {
    o.setName(name).setDescription(desc).setRequired(!!req);
    if (extra.choices) o.addChoices(...extra.choices.map((c) => ({ name: c, value: c })));
    if (extra.min !== undefined) o.setMinValue(extra.min);
    if (extra.max !== undefined) o.setMaxValue(extra.max);
    if (extra.types) o.addChannelTypes(...extra.types);
    return o;
  });
}

const slashJSON = SPECS.map(([name, desc, opts = [], subs = null]) => {
  const b = new SlashCommandBuilder()
    .setName(name)
    .setDescription(desc)
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .setContexts(InteractionContextType.Guild);
  opts.forEach((o) => addOpt(b, o));
  if (subs) {
    for (const [sn, [sd, so]] of Object.entries(subs)) {
      b.addSubcommand((sc) => {
        sc.setName(sn).setDescription(sd);
        so.forEach((o) => addOpt(sc, o));
        return sc;
      });
    }
  }
  return b.toJSON();
});
const SPEC_BY_NAME = Object.fromEntries(SPECS.map((sp) => [sp[0], sp]));

async function registerCommands(guild) {
  try {
    await guild.commands.set(slashJSON);
    console.log(`Slash commands registered in: ${guild.name}`);
  } catch (err) {
    console.error(`Failed to register commands in ${guild.name}:`, err.message);
  }
}

// ============================================================
//  ADAPTER: slash interaction -> the shared "message" style handlers
// ============================================================
function buildArgs(interaction, spec) {
  const [, , opts = [], subs] = spec;
  const args = [];
  let optList = opts;
  if (subs) {
    const sub = interaction.options.getSubcommand();
    args.push(sub);
    optList = subs[sub][1];
  }
  for (const [, name] of optList) {
    const v = interaction.options.get(name)?.value;
    if (v === undefined || v === null) break;
    args.push(String(v));
  }
  return args;
}

function makeFakeMessage(interaction) {
  const state = { replied: false };
  const ch = interaction.options.getChannel('channel');
  const role = interaction.options.getRole('role');
  const msg = {
    id: interaction.id,
    guild: interaction.guild,
    channel: interaction.channel,
    author: interaction.user,
    member: interaction.member,
    mentions: {
      members: { first: () => undefined },
      channels: { first: () => ch || undefined },
      roles: { first: () => role || undefined }
    },
    delete: () => Promise.resolve(),
    reply: (payload) => {
      const p = asEmbed(payload);
      if (!state.replied) {
        state.replied = true;
        return interaction.editReply(p);
      }
      return interaction.followUp(p);
    }
  };
  return { msg, state };
}

const EPHEMERAL_CMDS = new Set(['purge', 'verifypanel']);

client.once(Events.ClientReady, async () => {
  console.log(`Logged in as ${client.user.tag}`);
  // Bot status (change the text below anytime)
  client.user.setPresence({
    status: 'online', // online | idle | dnd
    activities: [{ name: 'Custom Status', type: ActivityType.Custom, state: 'Updating Tome security' }]
  });
  for (const guild of client.guilds.cache.values()) await registerCommands(guild);
});
client.on(Events.GuildCreate, registerCommands);

// ============================================================
//  SLASH COMMAND HANDLER
// ============================================================
client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isChatInputCommand() || !interaction.guild) return;
  const cmd = interaction.commandName;

  if (!interaction.memberPermissions?.has(PermissionFlagsBits.Administrator)) {
    return interaction.reply({ ...failure('This command can only be used by **Administrators**.', 'Permission denied'), flags: MessageFlags.Ephemeral });
  }

  try {
    // ---------- /dm  (shows who sent it) ----------
    if (cmd === 'dm') {
      const user = interaction.options.getUser('user');
      const text = interaction.options.getString('message');
      await interaction.deferReply({ flags: MessageFlags.Ephemeral });
      try {
        const embed = new EmbedBuilder()
          .setColor(COLOR)
          .setTitle(`Message from ${interaction.guild.name}`)
          .setDescription(text)
          .addFields({
            name: 'Sent by',
            value: `${interaction.user.tag} (${interaction.member?.displayName ?? interaction.user.username})`
          })
          .setFooter({ text: `Sent by ${interaction.user.tag}`, iconURL: interaction.user.displayAvatarURL() })
          .setTimestamp();
        await user.send({ embeds: [embed] });
        await interaction.editReply(success('DM sent', `Delivered to **${user.tag}**.`, [{ name: 'Mode', value: 'Shows your name', inline: true }]));
      } catch (err) {
        await interaction.editReply(failure('Could not DM this user. Their DMs might be closed.', 'DM failed'));
      }
      return;
    }

    // ---------- /prvdm  (anonymous: no sender name) ----------
    if (cmd === 'prvdm') {
      const user = interaction.options.getUser('user');
      const text = interaction.options.getString('message');
      await interaction.deferReply({ flags: MessageFlags.Ephemeral });
      try {
        const embed = new EmbedBuilder()
          .setColor(COLOR)
          .setTitle(`Message from ${interaction.guild.name}`)
          .setDescription(text)
          .setTimestamp(); // Discord shows "Today at / Yesterday at 22:44"
        await user.send({ embeds: [embed] });
        await interaction.editReply(success('Anonymous DM sent', `Delivered to **${user.tag}**.`, [{ name: 'Mode', value: 'Sender hidden', inline: true }]));
      } catch (err) {
        await interaction.editReply(failure('Could not DM this user. Their DMs might be closed.', 'DM failed'));
      }
      return;
    }

    // ---------- all other security commands ----------
    const handler = commands[cmd];
    const spec = SPEC_BY_NAME[cmd];
    if (!handler || !spec) return;

    const ephemeral = EPHEMERAL_CMDS.has(cmd);
    await interaction.deferReply(ephemeral ? { flags: MessageFlags.Ephemeral } : {});

    const { msg, state } = makeFakeMessage(interaction);
    const args = buildArgs(interaction, spec);
    await handler({ message: msg, args, cfg: getConfig(interaction.guild.id) });

    // The handler answered in the channel itself (purge, verifypanel...) -> tidy up the pending reply
    if (!state.replied) {
      if (ephemeral) await interaction.deleteReply().catch(() => {});
      else await interaction.editReply(success('Done', 'The command was executed.')).catch(() => {});
    }
  } catch (err) {
    console.error(`Command "${cmd}" failed:`, err);
    const payload = failure('Something went wrong. Check my permissions and role position.', 'Command error');
    if (interaction.deferred || interaction.replied) await interaction.editReply(payload).catch(() => {});
    else await interaction.reply({ ...payload, flags: MessageFlags.Ephemeral }).catch(() => {});
  }
});

// ============================================================
//  MESSAGE HANDLER (AutoMod only — commands are slash commands)
// ============================================================
client.on(Events.MessageCreate, async (message) => {
  if (message.author.bot || !message.guild) return;
  if (!message.member) await message.guild.members.fetch(message.author.id).catch(() => {});
  if (!message.member) return;

  if (!isAutoModExempt(message.member) && !isBypassed(message)) {
    try {
      await runAutoMod(message);
    } catch (e) {
      console.error('AutoMod error:', e.message);
    }
  }
});

// ============================================================
//  MAINTENANCE: memory cleanup + graceful shutdown
// ============================================================
// Trackers only remove entries when a rule triggers, so sweep stale ones periodically.
setInterval(() => {
  const now = Date.now();
  const sweep = (map, windowMs) => {
    for (const [k, list] of map) {
      const last = list[list.length - 1];
      const t = typeof last === 'number' ? last : last?.t;
      if (!t || now - t > windowMs) map.delete(k);
    }
  };
  sweep(spamTracker, SPAM.windowMs * 2);
  sweep(dupTracker, DUPLICATE.windowMs * 2);
  sweep(strikeTracker, STRIKES.windowMs);
  sweep(nukeTracker, NUKE_WINDOW * 2);
  sweep(joinLog, RAID_WINDOW * 2);
  for (const [k, v] of captchas) if (v.expires < now) captchas.delete(k);
}, 5 * 60 * 1000).unref();

function shutdown(signal) {
  console.log(`${signal} received, saving data and shutting down...`);
  flushSave();
  client.destroy();
  process.exit(0);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('unhandledRejection', (err) => console.error('Unhandled rejection:', err));
process.on('uncaughtException', (err) => console.error('Uncaught exception:', err));
client.on(Events.Error, (err) => console.error('Client error:', err.message));

if (!TOKEN) {
  console.error('Bot token missing. Set the TOKEN environment variable (or fill in the TOKEN constant at the top of this file).');
  process.exit(1);
}
client.login(TOKEN);
