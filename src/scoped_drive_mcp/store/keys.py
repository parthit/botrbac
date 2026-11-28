"""Key names, limits and the few fixed values the stored records share."""

KEY_PREFIX = "sdm:"
ALLOWLIST_KEY = "allowlist"
# Items this person lets other people's assistants read (see external.py). Kept apart from
# ALLOWLIST_KEY so an item can be shared with paired people without the owner's own bot
# seeing it, and the reverse.
EXTERNAL_ALLOWLIST_KEY = "ext_allowlist"
# Named roles (agent_roles.py): each is a part of ALLOWLIST_KEY with its own ceiling.
AGENT_ROLES_KEY = "agent_roles"
# Who may read an external entry: AUDIENCE_LINKED is anyone with an active pairing with
# the owner; otherwise the entry names the people (a tuple of emails) who may read it.
AUDIENCE_LINKED = "linked"
# What the people who can see an external entry may do with it.
ACCESS_READ = "read"
ACCESS_EDIT = "edit"
# What this person's assistants may read in Notion (chosen on Files, "From Notion").
NOTION_ALLOWLIST_KEY = "notion_allowlist"
# What this person's assistants may read in OneDrive (chosen on Files, "From OneDrive").
ONEDRIVE_ALLOWLIST_KEY = "onedrive_allowlist"
ACTIVITY_KEY = "activity"
# Changes (writes, dashboard actions, messages): kept apart so reads cannot push them out.
ACTIVITY_CHANGES_KEY = "activity:changes"
ACTIVITY_MAX = 500
# A paired person's repeated call is written to the owner's Activity this often.
GUEST_ROW_EVERY = 3600
OWNER_TOKEN_KEY = "vault:owner_refresh_token"  # noqa: S105 - a key name
BOT_TOKEN_KEY = "vault:bot_refresh_token"  # noqa: S105 - a key name
NOTION_TOKEN_KEY = "vault:notion_token"  # noqa: S105 - a key name
ONEDRIVE_TOKEN_KEY = "vault:onedrive_token"  # noqa: S105 - a key name
USERS_INDEX = "users:index"
REDIS_IMPORT_FLAG = "sdm:meta:redis_admin_imported"  # on the raw store, not the sdm: view
REDIS_IMPORT_LOCK = "sdm:meta:redis_admin_import_lock"  # same raw store; expires if a copy dies
REDIS_IMPORT_LOCK_TTL = 120
