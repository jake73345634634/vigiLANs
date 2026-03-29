### 🔥 vigiLANs

---

A web app that takes the tedious out of firewall rule audits. Upload your firewall rule exports, and vigiLANs parses every rule, flags security issues, and presents everything in one place.

It doesn't replace your firewall management tools — it just makes auditing ACLs less soul-destroying. No more manually reviewing hundreds of rules or grepping through exports for overly permissive policies.

**Currently supports:** FortiGate (`.conf`, `.txt` rule exports)

---

#### Requirements

- Python 3.11+

---

#### Usage

```bash
git clone https://github.com/yourusername/vigiLANs.git
cd vigiLANs
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
cp mappings.example.json mappings.json
flask --app vigilans.app:create_app run
```

Then open [http://localhost:5000](http://localhost:5000) in your browser.

---

#### Mappings

vigiLANs uses a `mappings.json` file at the project root to control how parser-generated issues are presented in the UI. Each entry maps an issue title to a finding with optional configuration:

- **`findingName`** — optional custom display name (defaults to the issue title)
- **`columns`** — which columns to show in the rules table for this finding (defaults to all)
- **`evidence`** — optional evidence strings
- **`comments`** — optional notes

Issues not listed in `findings` will appear as unparsed. Issues listed in `ignored` will be hidden entirely.

The `EXAMPLE_FINDING` entry defines the default columns shown in the "All Rules" view.

See `mappings.example.json` for the structure.
