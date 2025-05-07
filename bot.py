# bot.py

import os
import json
import time
import hmac
import hashlib
from typing import Optional
from datetime import datetime, date

import discord
import aiohttp
from aiohttp import web
from discord.ext import commands
from discord import app_commands, Interaction, TextChannel, Forbidden
from discord.ui import View, Button
from dotenv import load_dotenv

# ─── Load & validate environment ────────────────────────────────────────────────
load_dotenv()

DISCORD_TOKEN       = os.getenv("DISCORD_TOKEN")
DIDIT_CLIENT_ID     = os.getenv("DIDIT_CLIENT_ID")
DIDIT_CLIENT_SECRET = os.getenv("DIDIT_CLIENT_SECRET")
DIDIT_AUTH_URL      = os.getenv("DIDIT_AUTH_URL")      # e.g. https://apx.didit.me/auth/v2/token/
DIDIT_SESSION_URL   = os.getenv("DIDIT_SESSION_URL")   # e.g. https://verification.didit.me/v1/session/
DIDIT_REDIRECT_URL  = os.getenv("DIDIT_REDIRECT_URL")  # e.g. https://my-public-domain.com/redirect
WEBHOOK_SECRET_KEY  = os.getenv("WEBHOOK_SECRET_KEY")
WEBHOOK_HOST        = os.getenv("WEBHOOK_HOST", "0.0.0.0")
WEBHOOK_PORT        = int(os.getenv("WEBHOOK_PORT", 8000))

CONFIG_PATH = "config.json"

# Ensure required envs
for var in (
    "DISCORD_TOKEN",
    "DIDIT_CLIENT_ID", "DIDIT_CLIENT_SECRET",
    "DIDIT_AUTH_URL", "DIDIT_SESSION_URL", "DIDIT_REDIRECT_URL",
    "WEBHOOK_SECRET_KEY"
):
    if not globals().get(var):
        raise RuntimeError(f"Missing required environment variable: {var}")

# ─── JSON-backed config (now with sessions) ────────────────────────────────────
def load_config():
    if os.path.isfile(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    return {}

def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

config = load_config()
config.setdefault("redirect_channel", {})
config.setdefault("verified_role", {})
config.setdefault("sessions", {})   # store session → { guild, user, [username] }

# ─── Helpers: fetching Didit token ───────────────────────────────────────────────
async def get_access_token() -> str:
    auth = aiohttp.BasicAuth(DIDIT_CLIENT_ID, DIDIT_CLIENT_SECRET)
    data = {"grant_type": "client_credentials"}
    async with aiohttp.ClientSession() as session:
        async with session.post(DIDIT_AUTH_URL, data=data, auth=auth) as resp:
            resp.raise_for_status()
            return (await resp.json())["access_token"]

# ─── Verify Button View ─────────────────────────────────────────────────────────
class VerifyView(View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(
        label="Verify",
        style=discord.ButtonStyle.primary,
        custom_id="didit_verify_button"
    )
    async def verify_button(self, interaction: Interaction, button: Button):
        # 1) Only defer once—privately
        await interaction.response.defer(ephemeral=True)

        try:
            token = await get_access_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            guild_id = interaction.guild.id
            user_id  = interaction.user.id

            redirect_url = (
                f"{DIDIT_REDIRECT_URL}"
                f"?guild={guild_id}&user={user_id}"
            )
            payload = {
                "callback": redirect_url,
                "vendor_data": json.dumps({
                    "guild": guild_id,
                    "user": user_id
                })
            }

            async with aiohttp.ClientSession() as session_http:
                async with session_http.post(
                    DIDIT_SESSION_URL, json=payload, headers=headers
                ) as resp:
                    resp.raise_for_status()
                    data = await resp.json()

            # Save the session…
            session_id = data.get("session_id")
            if session_id:
                config["sessions"][session_id] = {
                    "guild": guild_id,
                    "user": user_id
                }
                save_config(config)

            session_url = data.get("url") or data.get("session_url")
            if not session_url:
                raise KeyError("Missing session URL")

            # 2) Then send exactly one follow-up privately
            embed = discord.Embed(
                title="🔗 Complete Your Verification",
                description=(
                    "Click **Start Verification** below to open the secure identification flow.\n"
                    "Once you finish, you’ll get your age-based role(s)."
                ),
                color=discord.Color.blue()
            )
            link_view = View()
            link_view.add_item(Button(label="Start Verification", url=session_url))

            await interaction.followup.send(
                embed=embed,
                view=link_view,
                ephemeral=True
            )

        except Exception as e:
            print("Error creating Didit session:", e)
            # only one follow-up total—if we hit error, we reuse it
            await interaction.followup.send(
                "❌ Failed to start verification. Please try again later.",
                ephemeral=True
            )


# ─── AIOHTTP Logging Middleware ─────────────────────────────────────────────────
@web.middleware
async def logging_middleware(request, handler):
    print(f"\n[HTTP] {request.remote} → {request.method} {request.path}")
    if request.can_read_body:
        body = await request.text()
        print("    Body:", body)
    try:
        resp = await handler(request)
        print(f"[HTTP] ← {resp.status}\n")
        return resp
    except Exception as ex:
        print(f"[HTTP] ← Exception:\n    {ex}\n")
        raise

# ─── Webhook Handler ────────────────────────────────────────────────────────────
def verify_signature(body: str, sig: str, ts: str) -> bool:
    if not sig or not ts:
        return False
    if abs(time.time() - int(ts)) > 300:
        return False
    comp = hmac.new(
        WEBHOOK_SECRET_KEY.encode(), body.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(comp, sig)

async def handle_webhook(request: web.Request) -> web.Response:
    body = await request.text()
    sig  = request.headers.get("x-signature")
    ts   = request.headers.get("x-timestamp")
    if not verify_signature(body, sig, ts):
        raise web.HTTPUnauthorized()

    data        = json.loads(body)
    status      = data.get("status")       # e.g. "Approved", "Denied", etc.
    session_id  = data.get("session_id")
    vendor_data = data.get("vendor_data")

    # early exit on missing vendor data
    if not vendor_data or not session_id:
        return web.Response(text="OK")

    info   = json.loads(vendor_data)
    guild  = bot.get_guild(info["guild"])
    member = guild.get_member(info["user"])
    roles_cfg = config["verified_role"].get(str(guild.id))

    assigned = []

    if status == "Approved":
        # fetch their DOB and assign roles as before…
        try:
            token = await get_access_token()
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            decision_url = f"{DIDIT_SESSION_URL}{session_id}/decision/"
            async with aiohttp.ClientSession() as sess2:
                async with sess2.get(decision_url, headers=headers) as resp2:
                    resp2.raise_for_status()
                    decision = await resp2.json()

            dob = decision.get("kyc", {}).get("date_of_birth")
            if dob:
                birth = datetime.strptime(dob, "%Y-%m-%d").date()
                today = date.today()
                age = today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))

                # age‐threshold logic (dict or int)
                if isinstance(roles_cfg, dict):
                    for thr, role_id in roles_cfg.items():
                        if age >= int(thr):
                            role = guild.get_role(role_id)
                            if role:
                                await member.add_roles(role)
                                assigned.append(f"{role.name} ({thr}+)")
                elif isinstance(roles_cfg, int):
                    role = guild.get_role(roles_cfg)
                    if role:
                        await member.add_roles(role)
                        assigned.append(role.name)

            # persist username
            config["sessions"].setdefault(session_id, {})["username"] = str(member)
            save_config(config)

        except Exception as e:
            print(f"⚠️ Error assigning roles or fetching decision: {e}")

        # now DM based on assigned list
        if assigned:
            # Success
            try:
                embed = discord.Embed(
                    title="✅ Verification Complete",
                    description=(
                        "You’ve successfully finished verification and have been granted: "
                        f"**{', '.join(assigned)}**"
                    ),
                    color=discord.Color.green()
                )
                await member.send(embed=embed)
                print(f"✅ Sent success DM to {member}")
            except Exception as e:
                print(f"❌ Failed to send success DM to {member}: {e}")

        else:
            # Underage / no matching role
            try:
                embed = discord.Embed(
                    title="❌ Verification Not Eligible",
                    description=(
                        "It looks like you didn’t meet our age requirements for any role. "
                        "If you believe this is an error, please contact a server administrator."
                    ),
                    color=discord.Color.red()
                )
                await member.send(embed=embed)
                print(f"⚠️ Sent underage DM to {member}")
            except Exception as e:
                print(f"❌ Failed to send underage DM to {member}: {e}")

    else:
        # status != Approved → outright failure
        try:
            embed = discord.Embed(
                title="❌ Verification Failed",
                description=(
                    "Your verification did not complete successfully. "
                    "Feel free to try again or contact support if you need help."
                ),
                color=discord.Color.red()
            )
            await member.send(embed=embed)
            print(f"⚠️ Sent failure DM to {member} (status={status})")
        except Exception as e:
            print(f"❌ Failed to send failure DM to {member}: {e}")

    return web.Response(text="OK")


# ─── Redirect Handler ────────────────────────────────────────────────────────────
async def handle_redirect(request: web.Request) -> web.Response:
    guild_id = request.query.get("guild")
    user_id  = request.query.get("user")
    if not guild_id or not user_id:
        return web.Response(
            text="Missing parameters",
            status=400,
            content_type="text/plain"
        )

    chan_id = config["redirect_channel"].get(guild_id)
    if not chan_id:
        return web.Response(
            text="❌ No redirect channel set. Run /set-redirect-channel.",
            status=404,
            content_type="text/plain"
        )

    link = f"https://discord.com/channels/{guild_id}/{chan_id}"
    html = f"""
    <html><head>
      <meta http-equiv="refresh" content="0;url={link}">
      <script>window.location.href = "{link}";</script>
    </head><body>
      Redirecting… <a href="{link}">Click here</a>
    </body></html>
    """
    return web.Response(
        body=html,
        content_type="text/html"
    )


# ─── Build & start HTTP server ─────────────────────────────────────────────────
def make_webapp() -> web.Application:
    app = web.Application(middlewares=[logging_middleware])
    app.router.add_post("/webhook", handle_webhook)
    app.router.add_get("/redirect", handle_redirect)
    return app

async def start_http():
    runner = web.AppRunner(make_webapp())
    await runner.setup()
    site = web.TCPSite(runner, WEBHOOK_HOST, WEBHOOK_PORT)
    await site.start()
    print(f"🚀 HTTP server listening on http://{WEBHOOK_HOST}:{WEBHOOK_PORT}")

# ─── Discord Bot Setup ─────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.members = True
bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    print(f"✅ Bot ready as {bot.user} (ID {bot.user.id})")

@bot.event
async def setup_hook():
    bot.loop.create_task(start_http())
    bot.add_view(VerifyView())
    await bot.tree.sync()

# ─── Slash Commands ──────────────────────────────────────────────────────────────
@bot.tree.command(
    name="spawn-identity-button",
    description="(Admin) Send the Identity Verifier embed with a Verify button"
)
async def spawn_identity_button(interaction: Interaction):
    # 1) Admin check
    if not interaction.user.guild_permissions.manage_guild:
        return await interaction.response.send_message(
            "❌ You need **Manage Server** permission.", ephemeral=True
        )

    # 2) Defer ephemerally (shows spinner, only you see it)
    await interaction.response.defer(ephemeral=True)

    embed = discord.Embed(
        title="👋 Quick Age Check",
        description=(
            "Hi there! We just need a fast, private check of your age to keep our community safe. "
            "Only the minimum info needed for age verification is collected—nothing more is stored or shared."
        ),
        color=discord.Color.blurple(),
    )

    # Optional: set a banner image for extra flair
    embed.set_image(url="https://example.com/banner.png")

    # Set an author—could be your server name or “Verification Bot”
    embed.set_author(
        name="Server Verification",
        icon_url="https://example.com/your-logo.png"
    )

    # Thumbnail in case you prefer a smaller icon instead of/in addition to the author icon
    embed.set_thumbnail(url="https://example.com/your-logo.png")

    # Single, tight Privacy & Security field
    embed.add_field(
        name="🔒 Privacy & Security",
        value=(
            "• Partnered with **Didit** for age checks—only your DOB is used.\n"
            "• Dual-encrypted (AES-256-GCM + hardware vaults) and signed with ECC P-256/ECDSA.\n"            
            "• Fully GDPR-compliant & ISO 27001-certified.\n"
            "• Data auto-purged once your 18+ or 21+ role is applied."
        ),
        inline=False
    )

    # Footer with a thank-you message
    embed.set_footer(
        text="Thanks for helping keep our community awesome! ❤️",
    )

    view = VerifyView()
    await interaction.channel.send(embed=embed, view=view)

    # 4) Replace your thinking spinner with a private “done” message
    await interaction.followup.send("✅ Button Created!", ephemeral=True)



@bot.tree.command(
    name="set-redirect-channel",
    description="(Admin) Choose the channel users land in after verification"
)
@app_commands.describe(channel="Channel to redirect users to once they finish KYC")
async def set_redirect_channel(
    interaction: Interaction,
    channel: TextChannel
):
    if not interaction.user.guild_permissions.manage_guild:
        return await interaction.response.send_message(
            "❌ You need **Manage Server** permission.", ephemeral=True
        )
    gid = str(interaction.guild.id)
    config["redirect_channel"][gid] = channel.id
    save_config(config)
    await interaction.response.send_message(
        f"✅ Post-verification users will land in {channel.mention}.",
        ephemeral=True
    )

@bot.tree.command(
    name="set-verified-role",
    description="(Admin) Pick the role to assign after KYC, optionally by age"
)
@app_commands.describe(
    role="The role to grant users once they finish verification",
    age="Age threshold (18 or 21). Omit to apply for both 18+ and 21+"
)
async def set_verified_role(
    interaction: Interaction,
    role: discord.Role,
    age: Optional[int] = None
):
    if not interaction.user.guild_permissions.manage_guild:
        return await interaction.response.send_message(
            "❌ You need **Manage Server** permission.", ephemeral=True
        )

    gid = str(interaction.guild.id)
    if age is None:
        config["verified_role"][gid] = {"18": role.id, "21": role.id}
        msg = f"✅ Role for 18+ and 21+ set to {role.mention}"
    else:
        if age not in (18, 21):
            return await interaction.response.send_message(
                "❌ Age must be either 18 or 21.", ephemeral=True
            )
        cfg = config["verified_role"].setdefault(gid, {})
        if isinstance(cfg, int):
            cfg = {}
        cfg[str(age)] = role.id
        config["verified_role"][gid] = cfg
        msg = f"✅ Role for {age}+ set to {role.mention}"

    save_config(config)
    await interaction.response.send_message(msg, ephemeral=True)

# ─── Entrypoint ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    bot.run(DISCORD_TOKEN)