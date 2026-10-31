# Harvey for Key Shift London: setup on your Mac

1. Get Harvey (v0.3.0, already in your skills-lock.json):
   git clone https://github.com/ethanplusai/harvey.git && cd harvey
   python3.13 -m venv .venv && source .venv/bin/activate && pip install -e .
   cp .env.example .env
2. Copy this pack in:
   - harvey.local.yaml            -> harvey/harvey.local.yaml
   - skills/product_knowledge.md  -> harvey/skills/product_knowledge.md
   Do NOT run `harvey train` afterwards: it would overwrite both files.
3. Make sure `claude login` is done (Harvey uses your Claude subscription).
4. Connect the mailbox: `harvey gmail` (hello@keyshiftlondon.org).
5. Finding youth charities and sports academies needs Serper (2,500 free
   searches, no card). Add SERPER_API_KEY to .env. OpenStreetMap, the default,
   cannot find these organisations.
6. `harvey signals --confirm free`, then `harvey discover --estimate`, then
   `harvey discover --provider serper`.
7. `harvey dashboard` and review every draft in the Outbox before it sends.
   Then `harvey run`.

## Settings in this pack
- Sender: Emmanuel Adeyemi, hello@keyshiftlondon.org
- Targets: youth charities, youth clubs, sports/football/boxing academies in
  Croydon, Lambeth, Southwark. Titles: CEO, Founder, Director, Programme
  Manager, Youth Work Manager, Safeguarding Lead, Academy Manager, Player
  Welfare Officer.
- Offer: free Level 1 training or a 20-minute call (your cal.com link).
- Max 15 emails a day, every one needs your approval. Weekdays 09:00-16:00
  London time. LinkedIn off.
- UK compliance: Precleared check on every new recipient (needed because some
  small charities and clubs count as individuals under PECR and need consent).

## Check before first send
- compliance.postal_address: add your full street address.
- Main domain risk: keep it at 10-15 a day and stop if bounces go over ~3%.
